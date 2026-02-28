package proxy

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/skarard/openclaw-auth-proxy/internal/config"
	"github.com/skarard/openclaw-auth-proxy/internal/policy"
)

func TestUpstreamCredentialInjection(t *testing.T) {
	var gotAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(200)
		w.Write([]byte("upstream-ok"))
	}))
	defer upstream.Close()

	// Parse the upstream URL to get the host
	upHost := hostFromURL(upstream.URL)
	upPort := strings.Split(strings.Split(upstream.URL, "//")[1], ":")[1]

	cfg := &config.Config{
		Agents: map[string]config.Agent{"agent1": {IP: "127.0.0.1"}},
		Rules: []config.Rule{{
			Agent: "agent1", Host: upHost, Credential: "cred1",
			Routes: []config.Route{{Method: "GET", Path: "/**"}},
		}},
		Default: "deny",
	}
	engine := policy.NewEngine(cfg)
	creds := &CredentialStore{values: map[string]string{"cred1": "tok-xyz"}}
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))

	us := config.Upstream{
		Name:       "test",
		ListenPort: 0, // not used in direct test
		Target:     "http://" + upHost + ":" + upPort,
	}
	up, err := NewUpstreamProxy(us, engine, creds, logger, false)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("GET", "/api/foo", nil)
	req.RemoteAddr = "127.0.0.1:9999"
	w := httptest.NewRecorder()
	up.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Errorf("status = %d, want 200", w.Code)
	}
	if gotAuth != "Bearer tok-xyz" {
		t.Errorf("auth = %q, want 'Bearer tok-xyz'", gotAuth)
	}
	if w.Body.String() != "upstream-ok" {
		t.Errorf("body = %q", w.Body.String())
	}
}

func TestUpstreamPolicyDenied(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("upstream should not be called")
	}))
	defer upstream.Close()

	upHost := hostFromURL(upstream.URL)
	upPort := strings.Split(strings.Split(upstream.URL, "//")[1], ":")[1]

	cfg := &config.Config{
		Agents: map[string]config.Agent{"agent1": {IP: "127.0.0.1"}},
		Rules: []config.Rule{{
			Agent: "agent1", Host: upHost, Credential: "cred1",
			Routes: []config.Route{{Method: "GET", Path: "/allowed/**"}},
		}},
		Default: "deny",
	}
	engine := policy.NewEngine(cfg)
	creds := &CredentialStore{values: map[string]string{"cred1": "tok"}}
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))

	us := config.Upstream{Name: "test", Target: "http://" + upHost + ":" + upPort}
	up, _ := NewUpstreamProxy(us, engine, creds, logger, false)

	req := httptest.NewRequest("GET", "/denied/path", nil)
	req.RemoteAddr = "127.0.0.1:9999"
	w := httptest.NewRecorder()
	up.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
}

func TestUpstreamUnknownAgent(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer upstream.Close()

	cfg := &config.Config{
		Agents:  map[string]config.Agent{"agent1": {IP: "127.0.0.1"}},
		Default: "deny",
	}
	engine := policy.NewEngine(cfg)
	creds := &CredentialStore{values: map[string]string{}}
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))

	us := config.Upstream{Name: "test", Target: upstream.URL}
	up, _ := NewUpstreamProxy(us, engine, creds, logger, false)

	req := httptest.NewRequest("GET", "/foo", nil)
	req.RemoteAddr = "10.0.0.1:9999" // unknown
	w := httptest.NewRecorder()
	up.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
}
