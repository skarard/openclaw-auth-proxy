package policy

import (
	"testing"

	"github.com/skarard/openclaw-auth-proxy/internal/config"
)

func testConfig() *config.Config {
	return &config.Config{
		Agents: map[string]config.Agent{
			"pa":        {IP: "172.20.0.10"},
			"teslacoil": {IP: "172.20.0.11"},
		},
		Rules: []config.Rule{
			{
				Agent:      "pa",
				Host:       "api.github.com",
				Credential: "github-pa",
				Routes: []config.Route{
					{Method: "GET", Path: "/**"},
					{Method: "POST", Path: "/repos/*/issues"},
					{Method: "PATCH", Path: "/repos/*/issues/*"},
				},
			},
			{
				Agent:      "teslacoil",
				Host:       "api.github.com",
				Credential: "github-tc",
				Routes: []config.Route{
					{Method: []interface{}{"GET", "POST", "PATCH"}, Path: "/repos/skarard/teslacoil/**"},
				},
			},
		},
		Default: "deny",
	}
}

func TestAgentLookup(t *testing.T) {
	e := NewEngine(testConfig())

	agent, ok := e.AgentForIP("172.20.0.10:54321")
	if !ok || agent != "pa" {
		t.Fatalf("expected pa, got %q (ok=%v)", agent, ok)
	}

	_, ok = e.AgentForIP("172.20.0.99")
	if ok {
		t.Fatal("expected unknown agent")
	}
}

func TestAllowedRoutes(t *testing.T) {
	e := NewEngine(testConfig())

	tests := []struct {
		agent, method, host, path string
		want                      Decision
	}{
		// PA: GET anything on github
		{"pa", "GET", "api.github.com", "/repos/skarard/issues", AllowWithCredential},
		// PA: POST issues
		{"pa", "POST", "api.github.com", "/repos/skarard/issues", AllowWithCredential},
		// PA: PATCH specific issue
		{"pa", "PATCH", "api.github.com", "/repos/skarard/issues/42", AllowWithCredential},
		// PA: DELETE denied
		{"pa", "DELETE", "api.github.com", "/repos/skarard/pa/issues/42", Deny},
		// PA: wrong host denied
		{"pa", "GET", "github.com", "/skarard/pa", Deny},

		// TeslaCoil: GET in its repo
		{"teslacoil", "GET", "api.github.com", "/repos/skarard/teslacoil/issues", AllowWithCredential},
		// TeslaCoil: POST in its repo
		{"teslacoil", "POST", "api.github.com", "/repos/skarard/teslacoil/pulls", AllowWithCredential},
		// TeslaCoil: DELETE denied
		{"teslacoil", "DELETE", "api.github.com", "/repos/skarard/teslacoil/issues/1", Deny},
		// TeslaCoil: wrong repo denied
		{"teslacoil", "GET", "api.github.com", "/repos/skarard/pa/issues", Deny},
	}

	for _, tt := range tests {
		r := e.Evaluate(tt.agent, tt.method, tt.host, tt.path)
		if r.Decision != tt.want {
			t.Errorf("%s %s %s%s: got %v, want %v (rule: %s)",
				tt.agent, tt.method, tt.host, tt.path, r.Decision, tt.want, r.Rule)
		}
	}
}

func TestPathMatching(t *testing.T) {
	tests := []struct {
		pattern, path string
		want          bool
	}{
		{"/**", "/anything/at/all", true},
		{"/**", "/", true},
		{"/repos/*/issues", "/repos/skarard/issues", true},
		{"/repos/*/issues", "/repos/skarard/issues/42", false},
		{"/repos/*/issues/*", "/repos/skarard/issues/42", true},
		{"/repos/skarard/teslacoil/**", "/repos/skarard/teslacoil/pulls", true},
		{"/repos/skarard/teslacoil/**", "/repos/skarard/other/pulls", false},
	}

	for _, tt := range tests {
		got := pathMatches(tt.pattern, tt.path)
		if got != tt.want {
			t.Errorf("pathMatches(%q, %q) = %v, want %v", tt.pattern, tt.path, got, tt.want)
		}
	}
}
