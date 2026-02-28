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
			"noRules":   {IP: "172.20.0.12"},
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
				Agent:      "pa",
				Host:       "api.vercel.com",
				Credential: "vercel-pa",
				Routes: []config.Route{
					{Method: "GET", Path: "/v1/projects/**"},
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
		{"pa", "GET", "api.github.com", "/repos/skarard/issues", AllowWithCredential},
		{"pa", "POST", "api.github.com", "/repos/skarard/issues", AllowWithCredential},
		{"pa", "PATCH", "api.github.com", "/repos/skarard/issues/42", AllowWithCredential},
		{"pa", "DELETE", "api.github.com", "/repos/skarard/pa/issues/42", Deny},
		{"pa", "GET", "github.com", "/skarard/pa", Deny},

		{"teslacoil", "GET", "api.github.com", "/repos/skarard/teslacoil/issues", AllowWithCredential},
		{"teslacoil", "POST", "api.github.com", "/repos/skarard/teslacoil/pulls", AllowWithCredential},
		{"teslacoil", "DELETE", "api.github.com", "/repos/skarard/teslacoil/issues/1", Deny},
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
		// * should not match empty segments
		{"/repos/*/issues", "/repos//issues", false},
		// trailing slash
		{"/repos/skarard/teslacoil/**", "/repos/skarard/teslacoil/", true},
		// ** in middle of pattern
		{"/repos/**/issues", "/repos/a/b/c/issues", true},
		{"/repos/**/issues", "/repos/issues", true},
		{"/repos/**/issues", "/repos/a/issues", true},
		// exact match
		{"/exact", "/exact", true},
		{"/exact", "/exact/more", false},
	}

	for _, tt := range tests {
		got := pathMatches(tt.pattern, tt.path)
		if got != tt.want {
			t.Errorf("pathMatches(%q, %q) = %v, want %v", tt.pattern, tt.path, got, tt.want)
		}
	}
}

func TestDefaultDeny(t *testing.T) {
	cfg := testConfig()
	cfg.Default = "deny"
	e := NewEngine(cfg)

	r := e.Evaluate("pa", "GET", "unknown.com", "/")
	if r.Decision != Deny {
		t.Errorf("expected deny, got %v", r.Decision)
	}
}

func TestDefaultPassthrough(t *testing.T) {
	cfg := testConfig()
	cfg.Default = "passthrough"
	e := NewEngine(cfg)

	r := e.Evaluate("pa", "GET", "unknown.com", "/")
	if r.Decision != Allow {
		t.Errorf("expected allow (passthrough), got %v", r.Decision)
	}
}

func TestMultipleRulesSameAgentDifferentHosts(t *testing.T) {
	e := NewEngine(testConfig())

	// pa has rules for github and vercel
	r := e.Evaluate("pa", "GET", "api.vercel.com", "/v1/projects/foo")
	if r.Decision != AllowWithCredential || r.Credential != "vercel-pa" {
		t.Errorf("expected vercel-pa credential, got decision=%v cred=%s", r.Decision, r.Credential)
	}

	r = e.Evaluate("pa", "GET", "api.github.com", "/repos/x/y")
	if r.Decision != AllowWithCredential || r.Credential != "github-pa" {
		t.Errorf("expected github-pa credential, got decision=%v cred=%s", r.Decision, r.Credential)
	}
}

func TestMethodCaseInsensitivity(t *testing.T) {
	e := NewEngine(testConfig())

	r := e.Evaluate("pa", "get", "api.github.com", "/repos/skarard/foo")
	if r.Decision != AllowWithCredential {
		t.Errorf("expected allow for lowercase method, got %v", r.Decision)
	}
}

func TestEmptyRoutesMatchAllMethods(t *testing.T) {
	cfg := &config.Config{
		Agents: map[string]config.Agent{"a": {IP: "1.2.3.4"}},
		Rules: []config.Rule{{
			Agent: "a", Host: "example.com", Credential: "c",
			Routes: []config.Route{{Path: "/**"}}, // no method specified
		}},
		Default: "deny",
	}
	e := NewEngine(cfg)

	for _, m := range []string{"GET", "POST", "DELETE", "PATCH", "PUT"} {
		r := e.Evaluate("a", m, "example.com", "/foo")
		if r.Decision != AllowWithCredential {
			t.Errorf("method %s: expected allow, got %v", m, r.Decision)
		}
	}
}

func TestOverlappingPatternsFirstMatchWins(t *testing.T) {
	cfg := &config.Config{
		Agents: map[string]config.Agent{"a": {IP: "1.2.3.4"}},
		Rules: []config.Rule{
			{Agent: "a", Host: "example.com", Credential: "first",
				Routes: []config.Route{{Method: "GET", Path: "/api/**"}}},
			{Agent: "a", Host: "example.com", Credential: "second",
				Routes: []config.Route{{Method: "GET", Path: "/api/v1/**"}}},
		},
		Default: "deny",
	}
	e := NewEngine(cfg)

	r := e.Evaluate("a", "GET", "example.com", "/api/v1/foo")
	if r.Credential != "first" {
		t.Errorf("expected first match credential 'first', got %q", r.Credential)
	}
}

func TestAgentWithNoMatchingRules(t *testing.T) {
	e := NewEngine(testConfig())

	r := e.Evaluate("noRules", "GET", "api.github.com", "/anything")
	if r.Decision != Deny {
		t.Errorf("expected deny for agent with no rules, got %v", r.Decision)
	}
}

func TestStarDoesNotMatchEmpty(t *testing.T) {
	// /repos/*/issues should NOT match /repos//issues (cleaned to /repos/issues)
	got := pathMatches("/repos/*/issues", "/repos/issues")
	if got {
		t.Error("* should not match empty segment")
	}
}

func TestDoubleSlashesInPath(t *testing.T) {
	// path.Clean normalizes double slashes
	got := pathMatches("/api/**", "/api//v1/foo")
	if !got {
		t.Error("expected match after path cleaning of double slashes")
	}
}
