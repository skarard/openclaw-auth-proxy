package proxy

import (
	"io"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/skarard/openclaw-auth-proxy/internal/policy"
)

type Proxy struct {
	engine *policy.Engine
	creds  *CredentialStore
	client *http.Client
	logger *slog.Logger
	audit  bool
}

func New(engine *policy.Engine, creds *CredentialStore, logger *slog.Logger, audit bool) *Proxy {
	return &Proxy{
		engine: engine,
		creds:  creds,
		logger: logger,
		audit:  audit,
		client: &http.Client{
			Timeout: 120 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse // don't follow redirects, let agent handle them
			},
		},
	}
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// CONNECT method for HTTPS tunneling
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
		return
	}
	p.handleHTTP(w, r)
}

func (p *Proxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	agent, ok := p.engine.AgentForIP(r.RemoteAddr)
	if !ok {
		p.log(r, "", "unknown_agent", "deny")
		http.Error(w, "unknown agent", http.StatusForbidden)
		return
	}

	host := r.URL.Hostname()
	result := p.engine.Evaluate(agent, r.Method, host, r.URL.Path)

	if result.Decision == policy.Deny {
		p.log(r, agent, result.Rule, "deny")
		http.Error(w, "denied by policy", http.StatusForbidden)
		return
	}

	// Inject credential if needed
	if result.Decision == policy.AllowWithCredential && result.Credential != "" {
		token, ok := p.creds.Get(result.Credential)
		if !ok {
			p.log(r, agent, result.Rule, "credential_missing")
			http.Error(w, "AUTH_REQUIRED: credential not configured", http.StatusForbidden)
			return
		}
		r.Header.Set("Authorization", "Bearer "+token)
	}

	p.log(r, agent, result.Rule, "allow")

	// Forward request
	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, r.URL.String(), r.Body)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	// Copy headers (except hop-by-hop)
	for key, vals := range r.Header {
		if isHopByHop(key) {
			continue
		}
		for _, v := range vals {
			outReq.Header.Add(key, v)
		}
	}

	resp, err := p.client.Do(outReq)
	if err != nil {
		http.Error(w, "upstream error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Copy response headers
	for key, vals := range resp.Header {
		for _, v := range vals {
			w.Header().Add(key, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	agent, ok := p.engine.AgentForIP(r.RemoteAddr)
	if !ok {
		p.log(r, "", "unknown_agent", "deny")
		http.Error(w, "unknown agent", http.StatusForbidden)
		return
	}

	// For CONNECT, check host policy (no path/method scoping — it's a tunnel)
	host := r.URL.Hostname()
	result := p.engine.Evaluate(agent, "CONNECT", host, "/")

	if result.Decision == policy.Deny {
		p.log(r, agent, result.Rule, "deny")
		http.Error(w, "denied by policy", http.StatusForbidden)
		return
	}

	p.log(r, agent, result.Rule, "tunnel")

	// Establish tunnel
	destConn, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		http.Error(w, "could not reach upstream", http.StatusBadGateway)
		return
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		destConn.Close()
		return
	}

	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	go transfer(destConn, clientConn)
	go transfer(clientConn, destConn)
}

func transfer(dst, src net.Conn) {
	defer dst.Close()
	defer src.Close()
	io.Copy(dst, src)
}

func (p *Proxy) log(r *http.Request, agent, rule, decision string) {
	if !p.audit {
		return
	}
	p.logger.Info("request",
		"agent", agent,
		"method", r.Method,
		"host", r.URL.Hostname(),
		"path", r.URL.Path,
		"rule", rule,
		"decision", decision,
	)
}

func isHopByHop(key string) bool {
	switch http.CanonicalHeaderKey(key) {
	case "Connection", "Keep-Alive", "Proxy-Authenticate",
		"Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade":
		return true
	}
	return false
}
