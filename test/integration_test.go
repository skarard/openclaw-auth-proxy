package test

import (
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/skarard/openclaw-auth-proxy/internal/config"
	"github.com/skarard/openclaw-auth-proxy/internal/policy"
	"github.com/skarard/openclaw-auth-proxy/internal/proxy"
)

func TestIntegrationEndToEnd(t *testing.T) {
	var receivedAuth string
	var receivedMethod string
	var receivedPath string
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		receivedMethod = r.Method
		receivedPath = r.URL.Path
		w.Header().Set("X-Upstream", "real")
		w.WriteHeader(200)
		w.Write([]byte("upstream-response"))
	}))
	defer upstream.Close()

	upAddr := upstream.Listener.Addr().String()
	upHost, upPort, _ := net.SplitHostPort(upAddr)

	cfg := &config.Config{
		Agents: map[string]config.Agent{
			"agent1": {IP: "127.0.0.1"},
			"agent2": {IP: "127.0.0.2"},
		},
		Rules: []config.Rule{
			{
				Agent: "agent1", Host: upHost, Credential: "cred1",
				Routes: []config.Route{
					{Method: "GET", Path: "/**"},
					{Method: "POST", Path: "/api/data"},
				},
			},
			{
				Agent: "agent2", Host: upHost, Credential: "cred2",
				Routes: []config.Route{
					{Method: "GET", Path: "/public/**"},
				},
			},
		},
		Default: "deny",
	}
	engine := policy.NewEngine(cfg)

	t.Setenv("INT_CRED1", "token-agent1")
	t.Setenv("INT_CRED2", "token-agent2")
	credStore, err := proxy.NewCredentialStore(map[string]config.Cred{
		"cred1": {Source: "env", ID: "INT_CRED1"},
		"cred2": {Source: "env", ID: "INT_CRED2"},
	})
	if err != nil {
		t.Fatal(err)
	}

	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))

	usCfg := config.Upstream{
		Name:       "test-upstream",
		ListenPort: 0,
		Target:     "https://" + upHost + ":" + upPort,
	}
	up, err := proxy.NewUpstreamProxy(usCfg, engine, credStore, logger, false)
	if err != nil {
		t.Fatal(err)
	}
	up.SetTestTransport(&http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	})

	t.Run("agent1_allowed_get", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/foo", nil)
		req.RemoteAddr = "127.0.0.1:9999"
		w := httptest.NewRecorder()
		up.ServeHTTP(w, req)
		if w.Code != 200 {
			t.Errorf("status = %d, want 200", w.Code)
		}
		if receivedAuth != "Bearer token-agent1" {
			t.Errorf("auth = %q", receivedAuth)
		}
		if w.Body.String() != "upstream-response" {
			t.Errorf("body = %q", w.Body.String())
		}
	})

	t.Run("agent1_denied_delete", func(t *testing.T) {
		req := httptest.NewRequest("DELETE", "/api/foo", nil)
		req.RemoteAddr = "127.0.0.1:9999"
		w := httptest.NewRecorder()
		up.ServeHTTP(w, req)
		if w.Code != 403 {
			t.Errorf("status = %d, want 403", w.Code)
		}
	})

	t.Run("agent2_different_cred", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/public/info", nil)
		req.RemoteAddr = "127.0.0.2:9999"
		w := httptest.NewRecorder()
		up.ServeHTTP(w, req)
		if w.Code != 200 {
			t.Errorf("status = %d, want 200", w.Code)
		}
		if receivedAuth != "Bearer token-agent2" {
			t.Errorf("auth = %q, want 'Bearer token-agent2'", receivedAuth)
		}
	})

	t.Run("agent2_denied_private", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/secret", nil)
		req.RemoteAddr = "127.0.0.2:9999"
		w := httptest.NewRecorder()
		up.ServeHTTP(w, req)
		if w.Code != 403 {
			t.Errorf("status = %d, want 403", w.Code)
		}
	})

	t.Run("unknown_agent", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/public/info", nil)
		req.RemoteAddr = "10.10.10.10:9999"
		w := httptest.NewRecorder()
		up.ServeHTTP(w, req)
		if w.Code != 403 {
			t.Errorf("status = %d, want 403", w.Code)
		}
	})

	t.Run("agent1_post_route_restriction", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/data", strings.NewReader("payload"))
		req.RemoteAddr = "127.0.0.1:9999"
		w := httptest.NewRecorder()
		up.ServeHTTP(w, req)
		if w.Code != 200 {
			t.Errorf("status = %d, want 200", w.Code)
		}
		if receivedMethod != "POST" {
			t.Errorf("method = %q", receivedMethod)
		}
		if receivedPath != "/api/data" {
			t.Errorf("path = %q", receivedPath)
		}
	})

	t.Run("agent1_post_wrong_path_denied", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/other", strings.NewReader("payload"))
		req.RemoteAddr = "127.0.0.1:9999"
		w := httptest.NewRecorder()
		up.ServeHTTP(w, req)
		if w.Code != 403 {
			t.Errorf("status = %d, want 403", w.Code)
		}
	})
}
