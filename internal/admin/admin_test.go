package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/skarard/openclaw-auth-proxy/internal/config"
)

func testConfig() *config.Config {
	return &config.Config{
		Listen:  config.Listen{Host: "0.0.0.0", Port: 3100},
		Logging: config.Logging{Level: "info"},
		Default: "deny",
		Agents: map[string]config.Agent{
			"pa": {IP: "172.20.0.10"},
		},
		Credentials: map[string]config.Cred{
			"github-pa": {Source: "env", ID: "GITHUB_TOKEN"},
		},
		Rules: []config.Rule{
			{Agent: "pa", Host: "api.github.com", Credential: "github-pa"},
		},
	}
}

func TestHealth(t *testing.T) {
	s := NewServer(testConfig(), nil, nil)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/health", nil)
	s.Handler().ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("status = %d", w.Code)
	}
}

func TestConfigRedacted(t *testing.T) {
	s := NewServer(testConfig(), nil, nil)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/config", nil)
	s.Handler().ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("status = %d", w.Code)
	}
	body := w.Body.String()
	// Should not contain actual credential values (there are none in this test,
	// but should contain source info)
	var out map[string]interface{}
	json.Unmarshal([]byte(body), &out)
	creds := out["credentials"].(map[string]interface{})
	ghCred := creds["github-pa"].(map[string]interface{})
	if ghCred["source"] != "env" {
		t.Errorf("source = %v", ghCred["source"])
	}
	// Should not have path or command fields leaked
	if _, ok := ghCred["path"]; ok {
		t.Error("path should not be in redacted output")
	}
}

func TestAgents(t *testing.T) {
	s := NewServer(testConfig(), nil, nil)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/agents", nil)
	s.Handler().ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("status = %d", w.Code)
	}
	var out map[string]AgentSummary
	json.Unmarshal(w.Body.Bytes(), &out)
	pa, ok := out["pa"]
	if !ok {
		t.Fatal("pa not in output")
	}
	if pa.IP != "172.20.0.10" {
		t.Errorf("ip = %q", pa.IP)
	}
	if len(pa.Services) != 1 || pa.Services[0] != "api.github.com" {
		t.Errorf("services = %v", pa.Services)
	}
}

func TestAuthAuditMounted(t *testing.T) {
	authHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("auth-ok"))
	})
	auditHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("audit-ok"))
	})

	s := NewServer(testConfig(), authHandler, auditHandler)

	// Test auth route
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/auth/pending", nil)
	s.Handler().ServeHTTP(w, r)
	if w.Body.String() != "auth-ok" {
		t.Errorf("auth body = %q", w.Body.String())
	}

	// Test audit route
	w = httptest.NewRecorder()
	r = httptest.NewRequest("GET", "/audit/recent", nil)
	s.Handler().ServeHTTP(w, r)
	if w.Body.String() != "audit-ok" {
		t.Errorf("audit body = %q", w.Body.String())
	}
}
