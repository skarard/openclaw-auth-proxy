package proxy

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/skarard/openclaw-auth-proxy/internal/policy"
)

func (p *Proxy) handleConnectMITM(w http.ResponseWriter, r *http.Request, agent string) {
	targetHost := r.URL.Hostname()
	targetPort := r.URL.Port()
	if targetPort == "" {
		targetPort = "443"
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer clientConn.Close()

	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	// TLS handshake with client
	// Use GetCertificate with fallback to targetHost when SNI is empty (e.g. IP addresses)
	tlsConfig := &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			host := hello.ServerName
			if host == "" {
				host = targetHost
			}
			return p.certManager.GetCertificateForHost(host)
		},
	}
	tlsConn := tls.Server(clientConn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		p.logger.Error("MITM TLS handshake failed", "host", targetHost, "error", err)
		return
	}
	defer tlsConn.Close()

	reader := bufio.NewReader(tlsConn)

	for {
		// Set read deadline to detect closed connections
		tlsConn.SetReadDeadline(time.Now().Add(60 * time.Second))

		req, err := http.ReadRequest(reader)
		if err != nil {
			if err != io.EOF && !isConnectionClosed(err) {
				p.logger.Error("MITM read request failed", "host", targetHost, "error", err)
			}
			return
		}

		// Set the full URL for policy evaluation
		req.URL.Scheme = "https"
		req.URL.Host = targetHost
		if targetPort != "443" {
			req.URL.Host = net.JoinHostPort(targetHost, targetPort)
		}

		p.handleMITMRequest(tlsConn, req, agent, targetHost, targetPort)
	}
}

func (p *Proxy) handleMITMRequest(conn net.Conn, req *http.Request, agent, targetHost, targetPort string) {
	result := p.engine.Evaluate(agent, req.Method, targetHost, req.URL.Path)

	if result.Decision == policy.Deny {
		p.logMITM(req, agent, result.Rule, "deny")
		resp := &http.Response{
			StatusCode: http.StatusForbidden,
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header:     make(http.Header),
			Body:       io.NopCloser(io.Reader(stringReader("denied by policy"))),
		}
		resp.Header.Set("Content-Type", "text/plain")
		resp.Write(conn)
		return
	}

	// Inject credential
	if result.Decision == policy.AllowWithCredential && result.Credential != "" {
		token, ok := p.creds.Get(result.Credential)
		if !ok {
			p.logMITM(req, agent, result.Rule, "credential_missing")
			resp := &http.Response{
				StatusCode: http.StatusForbidden,
				ProtoMajor: 1,
				ProtoMinor: 1,
				Header:     make(http.Header),
				Body:       io.NopCloser(stringReader("AUTH_REQUIRED: credential not configured")),
			}
			resp.Header.Set("Content-Type", "text/plain")
			resp.Write(conn)
			return
		}
		req.Header.Set("Authorization", "Bearer "+token)
	}

	// Strip Cookie headers from outbound request
	stripRequestCookies(req.Header)

	p.logMITM(req, agent, result.Rule, "allow")

	// Forward to real upstream
	upstreamURL := fmt.Sprintf("https://%s:%s%s", targetHost, targetPort, req.URL.RequestURI())
	outReq, err := http.NewRequest(req.Method, upstreamURL, req.Body)
	if err != nil {
		writeErrorResponse(conn, http.StatusBadRequest, "bad request")
		return
	}

	for key, vals := range req.Header {
		if isHopByHop(key) {
			continue
		}
		for _, v := range vals {
			outReq.Header.Add(key, v)
		}
	}

	client := p.getMITMClient()
	resp, err := client.Do(outReq)
	if err != nil {
		writeErrorResponse(conn, http.StatusBadGateway, "upstream error")
		return
	}
	defer resp.Body.Close()

	// Strip response headers
	stripSet := buildStripSet(result.StripResponseHeaders)
	stripResponseHeaders(resp.Header, stripSet)

	// Remove hop-by-hop from response
	for key := range resp.Header {
		if isHopByHop(key) {
			resp.Header.Del(key)
		}
	}

	resp.Write(conn)
}

func (p *Proxy) getMITMClient() *http.Client {
	if p.mitmClient != nil {
		return p.mitmClient
	}
	return p.client
}

func (p *Proxy) logMITM(r *http.Request, agent, rule, decision string) {
	if !p.audit {
		return
	}
	p.logger.Info("mitm-request",
		"agent", agent,
		"method", r.Method,
		"host", r.URL.Hostname(),
		"path", r.URL.Path,
		"rule", rule,
		"decision", decision,
	)
}

type stringReaderType struct {
	s string
	i int
}

func stringReader(s string) *stringReaderType {
	return &stringReaderType{s: s}
}

func (r *stringReaderType) Read(p []byte) (n int, err error) {
	if r.i >= len(r.s) {
		return 0, io.EOF
	}
	n = copy(p, r.s[r.i:])
	r.i += n
	return n, nil
}

func writeErrorResponse(conn net.Conn, status int, body string) {
	resp := &http.Response{
		StatusCode: status,
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     make(http.Header),
		Body:       io.NopCloser(stringReader(body)),
	}
	resp.Header.Set("Content-Type", "text/plain")
	resp.Write(conn)
}

func isConnectionClosed(err error) bool {
	if opErr, ok := err.(*net.OpError); ok {
		return opErr.Err.Error() == "use of closed network connection"
	}
	return false
}
