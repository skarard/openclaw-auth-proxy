package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/skarard/openclaw-auth-proxy/internal/config"
	"github.com/skarard/openclaw-auth-proxy/internal/policy"
)

// setupMITMTest creates a proxy with MITM enabled and a mock upstream HTTPS server.
// Returns: proxy listener addr, upstream server, CA cert pool, cleanup func
func setupMITMTest(t *testing.T, rules []config.Rule, creds map[string]string, defaultPolicy string) (string, *httptest.Server, *x509.CertPool, func()) {
	t.Helper()

	// Create upstream HTTPS server
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Auth", r.Header.Get("Authorization"))
		w.Header().Set("X-Cookie", r.Header.Get("Cookie"))
		w.Header().Set("Set-Cookie", "session=abc123")
		w.Header().Set("X-Custom", "upstream-value")
		w.WriteHeader(200)
		fmt.Fprintf(w, "OK from upstream: %s %s", r.Method, r.URL.Path)
	}))

	upstreamURL, _ := url.Parse(upstream.URL)
	upstreamHost := upstreamURL.Hostname()
	upstreamPort := upstreamURL.Port()

	// Fix rules to use upstream host
	for i := range rules {
		if rules[i].Host == "UPSTREAM" {
			rules[i].Host = upstreamHost
		}
	}

	cfg := &config.Config{
		Agents:  map[string]config.Agent{"test-agent": {IP: "127.0.0.1"}},
		Rules:   rules,
		Default: defaultPolicy,
	}

	credMap := make(map[string]config.Cred)
	for k := range creds {
		credMap[k] = config.Cred{Source: "env", ID: "TEST_CRED_" + strings.ToUpper(k)}
	}
	for k, v := range creds {
		os.Setenv("TEST_CRED_"+strings.ToUpper(k), v)
	}

	engine := policy.NewEngine(cfg)
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	credStore, err := NewCredentialStore(credMap)
	if err != nil {
		t.Fatalf("NewCredentialStore: %v", err)
	}

	// Generate CA
	caCertPEM, caKeyPEM, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	cm, err := NewCertManager(caCertPEM, caKeyPEM)
	if err != nil {
		t.Fatalf("NewCertManager: %v", err)
	}

	p := New(engine, credStore, logger, true)
	p.SetCertManager(cm)

	// Override MITM client to trust upstream's self-signed cert
	p.SetMITMClient(&http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	})

	// Start proxy listener
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go http.Serve(ln, p)

	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caCertPEM)

	cleanup := func() {
		ln.Close()
		upstream.Close()
		for k := range creds {
			os.Unsetenv("TEST_CRED_" + strings.ToUpper(k))
		}
	}

	_ = upstreamPort // used by the caller via the upstream URL
	return ln.Addr().String(), upstream, caPool, cleanup
}

func doMITMRequest(t *testing.T, proxyAddr string, caPool *x509.CertPool, targetURL string) *http.Response {
	t.Helper()

	proxyURL, _ := url.Parse("http://" + proxyAddr)
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				RootCAs: caPool,
			},
		},
	}

	resp, err := client.Get(targetURL)
	if err != nil {
		t.Fatalf("request through MITM proxy: %v", err)
	}
	return resp
}

func TestMITM_CredentialInjection(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Auth", r.Header.Get("Authorization"))
		fmt.Fprint(w, "ok")
	}))
	defer upstream.Close()

	upstreamURL, _ := url.Parse(upstream.URL)
	host := upstreamURL.Hostname()
	port := upstreamURL.Port()

	os.Setenv("TEST_MITM_TOKEN", "secret-token-123")
	defer os.Unsetenv("TEST_MITM_TOKEN")

	cfg := &config.Config{
		Agents: map[string]config.Agent{"test-agent": {IP: "127.0.0.1"}},
		Rules: []config.Rule{{
			Agent:      "test-agent",
			Host:       host,
			Credential: "github",
			Service:    "github",
			Routes:     []config.Route{{Method: "GET", Path: "/**"}},
		}},
		Default:     "deny",
		Credentials: map[string]config.Cred{"github": {Source: "env", ID: "TEST_MITM_TOKEN"}},
	}

	engine := policy.NewEngine(cfg)
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	credStore, _ := NewCredentialStore(cfg.Credentials)

	caCertPEM, caKeyPEM, _ := GenerateCA()
	cm, _ := NewCertManager(caCertPEM, caKeyPEM)

	p := New(engine, credStore, logger, true)
	p.SetCertManager(cm)
	p.SetMITMClient(&http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	})

	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go http.Serve(ln, p)

	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caCertPEM)

	proxyURL, _ := url.Parse("http://" + ln.Addr().String())
	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: caPool},
		},
	}

	resp, err := client.Get(fmt.Sprintf("https://%s:%s/repos/test", host, port))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}

	auth := resp.Header.Get("X-Auth")
	if auth != "Bearer secret-token-123" {
		t.Errorf("expected auth header, got: %q", auth)
	}
}

func TestMITM_PolicyDeny(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("upstream should not be reached")
	}))
	defer upstream.Close()

	// No rules = default deny
	cfg := &config.Config{
		Agents:  map[string]config.Agent{"test-agent": {IP: "127.0.0.1"}},
		Rules:   nil,
		Default: "deny",
	}

	engine := policy.NewEngine(cfg)
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	credStore, _ := NewCredentialStore(nil)

	caCertPEM, caKeyPEM, _ := GenerateCA()
	cm, _ := NewCertManager(caCertPEM, caKeyPEM)

	p := New(engine, credStore, logger, true)
	p.SetCertManager(cm)

	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go http.Serve(ln, p)

	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caCertPEM)

	upstreamURL, _ := url.Parse(upstream.URL)
	proxyURL, _ := url.Parse("http://" + ln.Addr().String())
	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: caPool},
		},
	}

	// The CONNECT itself will be denied (host-level check), so we expect a non-200 CONNECT response
	resp, err := client.Get(fmt.Sprintf("https://%s/test", upstreamURL.Host))
	if err != nil {
		// Expected — proxy denies CONNECT
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode == 200 {
		t.Error("expected deny, got 200")
	}
}

func TestMITM_SetCookieStripping(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "session=secret")
		w.Header().Set("X-Custom", "kept")
		fmt.Fprint(w, "ok")
	}))
	defer upstream.Close()

	upstreamURL, _ := url.Parse(upstream.URL)
	host := upstreamURL.Hostname()
	port := upstreamURL.Port()

	cfg := &config.Config{
		Agents: map[string]config.Agent{"test-agent": {IP: "127.0.0.1"}},
		Rules: []config.Rule{{
			Agent:   "test-agent",
			Host:    host,
			Service: "test",
			Routes:  []config.Route{{Method: "GET", Path: "/**"}},
		}},
		Default: "deny",
	}

	engine := policy.NewEngine(cfg)
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	credStore, _ := NewCredentialStore(nil)

	caCertPEM, caKeyPEM, _ := GenerateCA()
	cm, _ := NewCertManager(caCertPEM, caKeyPEM)

	p := New(engine, credStore, logger, true)
	p.SetCertManager(cm)
	p.SetMITMClient(&http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	})

	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go http.Serve(ln, p)

	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caCertPEM)

	proxyURL, _ := url.Parse("http://" + ln.Addr().String())
	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: caPool},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Get(fmt.Sprintf("https://%s:%s/test", host, port))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if cookie := resp.Header.Get("Set-Cookie"); cookie != "" {
		t.Errorf("Set-Cookie should be stripped, got: %q", cookie)
	}
	if custom := resp.Header.Get("X-Custom"); custom != "kept" {
		t.Errorf("X-Custom should be kept, got: %q", custom)
	}
}

func TestMITM_CookieHeaderStripping(t *testing.T) {
	var receivedCookie string
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedCookie = r.Header.Get("Cookie")
		fmt.Fprint(w, "ok")
	}))
	defer upstream.Close()

	upstreamURL, _ := url.Parse(upstream.URL)
	host := upstreamURL.Hostname()
	port := upstreamURL.Port()

	cfg := &config.Config{
		Agents: map[string]config.Agent{"test-agent": {IP: "127.0.0.1"}},
		Rules: []config.Rule{{
			Agent:   "test-agent",
			Host:    host,
			Service: "test",
			Routes:  []config.Route{{Method: "GET", Path: "/**"}},
		}},
		Default: "deny",
	}

	engine := policy.NewEngine(cfg)
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	credStore, _ := NewCredentialStore(nil)

	caCertPEM, caKeyPEM, _ := GenerateCA()
	cm, _ := NewCertManager(caCertPEM, caKeyPEM)

	p := New(engine, credStore, logger, true)
	p.SetCertManager(cm)
	p.SetMITMClient(&http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	})

	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go http.Serve(ln, p)

	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caCertPEM)

	proxyURL, _ := url.Parse("http://" + ln.Addr().String())
	transport := &http.Transport{
		Proxy:           http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{RootCAs: caPool},
	}

	req, _ := http.NewRequest("GET", fmt.Sprintf("https://%s:%s/test", host, port), nil)
	req.Header.Set("Cookie", "evil=session")

	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if receivedCookie != "" {
		t.Errorf("Cookie should be stripped, upstream got: %q", receivedCookie)
	}
}

func TestMITM_ResponseBodyForwarded(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(201)
		fmt.Fprint(w, `{"status":"created"}`)
	}))
	defer upstream.Close()

	upstreamURL, _ := url.Parse(upstream.URL)
	host := upstreamURL.Hostname()
	port := upstreamURL.Port()

	cfg := &config.Config{
		Agents: map[string]config.Agent{"test-agent": {IP: "127.0.0.1"}},
		Rules: []config.Rule{{
			Agent:   "test-agent",
			Host:    host,
			Service: "test",
			Routes:  []config.Route{{Method: "GET", Path: "/**"}},
		}},
		Default: "deny",
	}

	engine := policy.NewEngine(cfg)
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	credStore, _ := NewCredentialStore(nil)

	caCertPEM, caKeyPEM, _ := GenerateCA()
	cm, _ := NewCertManager(caCertPEM, caKeyPEM)

	p := New(engine, credStore, logger, true)
	p.SetCertManager(cm)
	p.SetMITMClient(&http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	})

	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go http.Serve(ln, p)

	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caCertPEM)

	proxyURL, _ := url.Parse("http://" + ln.Addr().String())
	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: caPool},
		},
	}

	resp, err := client.Get(fmt.Sprintf("https://%s:%s/test", host, port))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if string(body) != `{"status":"created"}` {
		t.Errorf("unexpected body: %s", body)
	}
}
