package proxy

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/skarard/openclaw-auth-proxy/internal/config"
	"github.com/skarard/openclaw-auth-proxy/internal/policy"
)

type UpstreamProxy struct {
	upstream  config.Upstream
	targetURL *url.URL
	engine    *policy.Engine
	creds     *CredentialStore
	client    *http.Client
	logger    *slog.Logger
	audit     bool
}

func NewUpstreamProxy(upstream config.Upstream, engine *policy.Engine, creds *CredentialStore, logger *slog.Logger, audit bool) (*UpstreamProxy, error) {
	u, err := url.Parse(upstream.Target)
	if err != nil {
		return nil, fmt.Errorf("parse upstream target %q: %w", upstream.Target, err)
	}
	return &UpstreamProxy{
		upstream:  upstream,
		targetURL: u,
		engine:    engine,
		creds:     creds,
		client: &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		logger: logger,
		audit:  audit,
	}, nil
}

// SetTestTransport replaces the HTTP client transport (for testing with self-signed certs).
func (up *UpstreamProxy) SetTestTransport(rt http.RoundTripper) {
	up.client.Transport = rt
}

func (up *UpstreamProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	agent, ok := up.engine.AgentForIP(r.RemoteAddr)
	if !ok {
		up.log(r, "", "unknown_agent", "deny")
		http.Error(w, "unknown agent", http.StatusForbidden)
		return
	}

	targetHost := up.targetURL.Hostname()
	result := up.engine.Evaluate(agent, r.Method, targetHost, r.URL.Path)

	if result.Decision == policy.Deny {
		up.log(r, agent, result.Rule, "deny")
		http.Error(w, "denied by policy", http.StatusForbidden)
		return
	}

	outURL := *up.targetURL
	outURL.Path = singleJoiningSlash(up.targetURL.Path, r.URL.Path)
	outURL.RawQuery = r.URL.RawQuery

	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, outURL.String(), r.Body)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	for key, vals := range r.Header {
		if isHopByHop(key) {
			continue
		}
		for _, v := range vals {
			outReq.Header.Add(key, v)
		}
	}
	outReq.Host = up.targetURL.Host

	if result.Credential != "" {
		token, ok := up.creds.Get(result.Credential)
		if !ok {
			up.log(r, agent, result.Rule, "credential_missing")
			http.Error(w, "AUTH_REQUIRED: credential not configured", http.StatusForbidden)
			return
		}
		outReq.Header.Set("Authorization", "Bearer "+token)
	}

	up.log(r, agent, result.Rule, "allow")

	resp, err := up.client.Do(outReq)
	if err != nil {
		http.Error(w, "upstream error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for key, vals := range resp.Header {
		for _, v := range vals {
			w.Header().Add(key, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func (up *UpstreamProxy) ListenAddr() string {
	return fmt.Sprintf("0.0.0.0:%d", up.upstream.ListenPort)
}

func (up *UpstreamProxy) log(r *http.Request, agent, rule, decision string) {
	if !up.audit {
		return
	}
	up.logger.Info("upstream-request",
		"upstream", up.upstream.Name,
		"agent", agent,
		"method", r.Method,
		"path", r.URL.Path,
		"rule", rule,
		"decision", decision,
	)
}

func StartUpstreamListeners(upstreams []config.Upstream, engine *policy.Engine, creds *CredentialStore, logger *slog.Logger, audit bool) ([]net.Listener, error) {
	var listeners []net.Listener
	for _, us := range upstreams {
		up, err := NewUpstreamProxy(us, engine, creds, logger, audit)
		if err != nil {
			for _, l := range listeners {
				l.Close()
			}
			return nil, err
		}
		addr := up.ListenAddr()
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			for _, l := range listeners {
				l.Close()
			}
			return nil, fmt.Errorf("listen upstream %s on %s: %w", us.Name, addr, err)
		}
		logger.Info("upstream listener started", "name", us.Name, "addr", addr, "target", us.Target)
		listeners = append(listeners, ln)
		go http.Serve(ln, up)
	}
	return listeners, nil
}

func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}
