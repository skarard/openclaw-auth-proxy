package proxy

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/skarard/openclaw-auth-proxy/internal/config"
	"github.com/skarard/openclaw-auth-proxy/internal/policy"
)

func setupProxy(t *testing.T, upstream *httptest.Server, defaultPolicy string) (*Proxy, *policy.Engine) {
	t.Helper()
	cfg := &config.Config{
		Agents: map[string]config.Agent{
			"agent1": {IP: "127.0.0.1"},
		},
		Rules: []config.Rule{
			{
				Agent:      "agent1",
				Host:       hostFromURL(upstream.URL),
				Credential: "test-cred",
				Routes: []config.Route{
					{Method: "GET", Path: "/**"},
					{Method: "POST", Path: "/**"},
				},
			},
		},
		Default: defaultPolicy,
	}
	engine := policy.NewEngine(cfg)
	creds := &CredentialStore{values: map[string]string{"test-cred": "token-abc"}}
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	p := New(engine, creds, logger, false)
	return p, engine
}

func hostFromURL(rawURL string) string {
	// e.g. "http://127.0.0.1:12345" -> "127.0.0.1"
	parts := strings.Split(rawURL, "//")
	hostPort := parts[1]
	host := strings.Split(hostPort, ":")[0]
	return host
}

func TestProxyForwardsRequest(t *testing.T) {
	var gotAuth, gotBody string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.Header().Set("X-Custom", "yes")
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	p, _ := setupProxy(t, upstream, "deny")

	// Build request targeting upstream
	req := httptest.NewRequest("POST", upstream.URL+"/test", strings.NewReader("hello"))
	req.RemoteAddr = "127.0.0.1:9999"
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("status = %d, want 201", w.Code)
	}
	if gotAuth != "Bearer token-abc" {
		t.Errorf("auth = %q, want 'Bearer token-abc'", gotAuth)
	}
	if gotBody != "hello" {
		t.Errorf("body = %q, want 'hello'", gotBody)
	}
	if w.Header().Get("X-Custom") != "yes" {
		t.Error("response header not forwarded")
	}
	if w.Body.String() != "ok" {
		t.Errorf("body = %q, want 'ok'", w.Body.String())
	}
}

func TestProxyDeniedRequest(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("upstream should not be called")
	}))
	defer upstream.Close()

	p, _ := setupProxy(t, upstream, "deny")

	req := httptest.NewRequest("DELETE", upstream.URL+"/test", nil)
	req.RemoteAddr = "127.0.0.1:9999"
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
}

func TestProxyUnknownAgent(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("upstream should not be called")
	}))
	defer upstream.Close()

	p, _ := setupProxy(t, upstream, "deny")

	req := httptest.NewRequest("GET", upstream.URL+"/test", nil)
	req.RemoteAddr = "10.0.0.1:9999" // unknown IP
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
}

func TestProxyMissingCredential(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer upstream.Close()

	cfg := &config.Config{
		Agents: map[string]config.Agent{"agent1": {IP: "127.0.0.1"}},
		Rules: []config.Rule{{
			Agent: "agent1", Host: hostFromURL(upstream.URL), Credential: "nonexistent",
			Routes: []config.Route{{Method: "GET", Path: "/**"}},
		}},
		Default: "deny",
	}
	engine := policy.NewEngine(cfg)
	creds := &CredentialStore{values: map[string]string{}} // no creds
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	p := New(engine, creds, logger, false)

	req := httptest.NewRequest("GET", upstream.URL+"/test", nil)
	req.RemoteAddr = "127.0.0.1:9999"
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
	if !strings.Contains(w.Body.String(), "AUTH_REQUIRED") {
		t.Errorf("body should contain AUTH_REQUIRED, got %q", w.Body.String())
	}
}

func TestProxyHopByHopStripped(t *testing.T) {
	var gotHeaders http.Header
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeaders = r.Header
		w.WriteHeader(200)
	}))
	defer upstream.Close()

	p, _ := setupProxy(t, upstream, "deny")

	req := httptest.NewRequest("GET", upstream.URL+"/test", nil)
	req.RemoteAddr = "127.0.0.1:9999"
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Proxy-Authorization", "Basic abc")
	req.Header.Set("X-Custom", "keep")
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if gotHeaders.Get("Connection") != "" {
		t.Error("Connection header should be stripped")
	}
	if gotHeaders.Get("Proxy-Authorization") != "" {
		t.Error("Proxy-Authorization header should be stripped")
	}
	if gotHeaders.Get("X-Custom") != "keep" {
		t.Error("X-Custom header should be forwarded")
	}
}

func TestProxyRedirectNotFollowed(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/other", http.StatusFound)
	}))
	defer upstream.Close()

	p, _ := setupProxy(t, upstream, "deny")

	req := httptest.NewRequest("GET", upstream.URL+"/test", nil)
	req.RemoteAddr = "127.0.0.1:9999"
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Errorf("status = %d, want 302", w.Code)
	}
}

func TestAuthRequiredStructuredJSON(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer upstream.Close()

	cfg := &config.Config{
		Agents: map[string]config.Agent{"agent1": {IP: "127.0.0.1"}},
		Rules: []config.Rule{{
			Agent: "agent1", Host: hostFromURL(upstream.URL), Credential: "nonexistent",
			Service: "github",
			Routes:  []config.Route{{Method: "GET", Path: "/**"}},
		}},
		Default: "deny",
	}
	engine := policy.NewEngine(cfg)
	creds := &CredentialStore{values: map[string]string{}}
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	p := New(engine, creds, logger, false)

	req := httptest.NewRequest("GET", upstream.URL+"/repos/test/issues", nil)
	req.RemoteAddr = "127.0.0.1:9999"
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("content-type = %q", ct)
	}

	var body map[string]string
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["error"] != "AUTH_REQUIRED" {
		t.Errorf("error = %q", body["error"])
	}
	if body["service"] != "github" {
		t.Errorf("service = %q", body["service"])
	}
	if body["agent"] != "agent1" {
		t.Errorf("agent = %q", body["agent"])
	}
	if body["request_id"] == "" {
		t.Error("request_id missing")
	}
	if body["message"] == "" {
		t.Error("message missing")
	}
}

func TestResponseSetCookieStripped(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "session=abc")
		w.Header().Set("X-Custom", "keep")
		w.WriteHeader(200)
	}))
	defer upstream.Close()

	p, _ := setupProxy(t, upstream, "deny")

	req := httptest.NewRequest("GET", upstream.URL+"/test", nil)
	req.RemoteAddr = "127.0.0.1:9999"
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Header().Get("Set-Cookie") != "" {
		t.Error("Set-Cookie should be stripped")
	}
	if w.Header().Get("X-Custom") != "keep" {
		t.Error("X-Custom should pass through")
	}
}

func TestCustomStripHeadersFromConfig(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "session=abc")
		w.Header().Set("X-OAuth-Token", "secret")
		w.Header().Set("X-Safe", "ok")
		w.WriteHeader(200)
	}))
	defer upstream.Close()

	cfg := &config.Config{
		Agents: map[string]config.Agent{"agent1": {IP: "127.0.0.1"}},
		Rules: []config.Rule{{
			Agent: "agent1", Host: hostFromURL(upstream.URL), Credential: "test-cred",
			StripResponseHeaders: []string{"X-OAuth-Token"},
			Routes:               []config.Route{{Method: "GET", Path: "/**"}},
		}},
		Default: "deny",
	}
	engine := policy.NewEngine(cfg)
	creds := &CredentialStore{values: map[string]string{"test-cred": "token-abc"}}
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	p := New(engine, creds, logger, false)

	req := httptest.NewRequest("GET", upstream.URL+"/test", nil)
	req.RemoteAddr = "127.0.0.1:9999"
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Header().Get("Set-Cookie") != "" {
		t.Error("Set-Cookie should be stripped (default)")
	}
	if w.Header().Get("X-OAuth-Token") != "" {
		t.Error("X-OAuth-Token should be stripped (custom)")
	}
	if w.Header().Get("X-Safe") != "ok" {
		t.Error("X-Safe should pass through")
	}
}

func TestCookieHeaderStrippedFromRequest(t *testing.T) {
	var gotCookie string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCookie = r.Header.Get("Cookie")
		w.WriteHeader(200)
	}))
	defer upstream.Close()

	p, _ := setupProxy(t, upstream, "deny")

	req := httptest.NewRequest("GET", upstream.URL+"/test", nil)
	req.RemoteAddr = "127.0.0.1:9999"
	req.Header.Set("Cookie", "session=hijack")
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if gotCookie != "" {
		t.Errorf("Cookie header should be stripped, got %q", gotCookie)
	}
}
