package config

import (
	"testing"
)

const v1YAML = `
agents:
  pa:
    ip: 172.20.0.10
  teslacoil:
    ip: 172.20.0.11

credentials:
  github-pa:
    source: env
    id: GITHUB_PA_TOKEN
  github-tc:
    source: env
    id: GITHUB_TC_TOKEN

rules:
  - agent: pa
    host: api.github.com
    credential: github-pa
    routes:
      - method: GET
        path: "/**"
      - method: POST
        path: "/repos/*/issues"

  - agent: teslacoil
    host: api.github.com
    credential: github-tc
    routes:
      - method: [GET, POST, PATCH]
        path: "/repos/skarard/teslacoil/**"

default: deny
listen:
  host: 0.0.0.0
  port: 3100
`

const v2YAML = `
version: 2

listen:
  host: 0.0.0.0
  port: 3100

credentials:
  github-pa:
    source: env
    id: GITHUB_PA_TOKEN
  github-tc:
    source: env
    id: GITHUB_TC_TOKEN

agents:
  pa:
    ip: 172.20.0.10
    services:
      github:
        host: api.github.com
        credential: github-pa
        routes:
          - method: GET
            path: "/**"
          - method: POST
            path: "/repos/*/issues"

  teslacoil:
    ip: 172.20.0.11
    services:
      github:
        host: api.github.com
        credential: github-tc
        routes:
          - method: [GET, POST, PATCH]
            path: "/repos/skarard/teslacoil/**"

default: deny
`

func TestParseV2(t *testing.T) {
	cfg, err := ParseAuto([]byte(v2YAML))
	if err != nil {
		t.Fatalf("parse v2: %v", err)
	}
	if cfg.Default != "deny" {
		t.Errorf("default = %q, want deny", cfg.Default)
	}
	if cfg.Listen.Port != 3100 {
		t.Errorf("port = %d, want 3100", cfg.Listen.Port)
	}
	if len(cfg.Agents) != 2 {
		t.Errorf("agents = %d, want 2", len(cfg.Agents))
	}
	if cfg.Agents["pa"].IP != "172.20.0.10" {
		t.Errorf("pa ip = %q", cfg.Agents["pa"].IP)
	}
	if len(cfg.Rules) == 0 {
		t.Fatal("no rules generated")
	}
}

func TestVersionDetection(t *testing.T) {
	cfg1, err := ParseAuto([]byte(v1YAML))
	if err != nil {
		t.Fatalf("v1: %v", err)
	}
	if len(cfg1.Rules) == 0 {
		t.Fatal("v1: no rules")
	}

	cfg2, err := ParseAuto([]byte(v2YAML))
	if err != nil {
		t.Fatalf("v2: %v", err)
	}
	if len(cfg2.Rules) == 0 {
		t.Fatal("v2: no rules")
	}
}

func TestV1V2StructuralEquivalence(t *testing.T) {
	cfg1, _ := ParseAuto([]byte(v1YAML))
	cfg2, _ := ParseAuto([]byte(v2YAML))

	// Same agents
	if len(cfg1.Agents) != len(cfg2.Agents) {
		t.Errorf("agents: v1=%d v2=%d", len(cfg1.Agents), len(cfg2.Agents))
	}
	for name, a1 := range cfg1.Agents {
		a2, ok := cfg2.Agents[name]
		if !ok {
			t.Errorf("v2 missing agent %q", name)
			continue
		}
		if a1.IP != a2.IP {
			t.Errorf("agent %q: v1.ip=%q v2.ip=%q", name, a1.IP, a2.IP)
		}
	}

	// Same credentials
	if len(cfg1.Credentials) != len(cfg2.Credentials) {
		t.Errorf("creds: v1=%d v2=%d", len(cfg1.Credentials), len(cfg2.Credentials))
	}

	// Same number of rules
	if len(cfg1.Rules) != len(cfg2.Rules) {
		t.Errorf("rules: v1=%d v2=%d", len(cfg1.Rules), len(cfg2.Rules))
	}

	// Same defaults
	if cfg1.Default != cfg2.Default {
		t.Errorf("default: v1=%q v2=%q", cfg1.Default, cfg2.Default)
	}

	// Verify rules contain same agent/host/credential combos
	type ruleKey struct{ agent, host, cred string }
	v1Keys := map[ruleKey]int{}
	v2Keys := map[ruleKey]int{}
	for _, r := range cfg1.Rules {
		v1Keys[ruleKey{r.Agent, r.Host, r.Credential}] += len(r.Routes)
	}
	for _, r := range cfg2.Rules {
		v2Keys[ruleKey{r.Agent, r.Host, r.Credential}] += len(r.Routes)
	}
	for k, v := range v1Keys {
		if v2Keys[k] != v {
			t.Errorf("rule %v: v1 routes=%d v2 routes=%d", k, v, v2Keys[k])
		}
	}
}

func TestInvalidV2(t *testing.T) {
	_, err := ParseAuto([]byte("version: 2\n  bad yaml"))
	if err == nil {
		t.Error("expected error for invalid yaml")
	}
}

func TestV2Defaults(t *testing.T) {
	cfg, err := ParseAuto([]byte("version: 2\nagents: {}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Default != "deny" {
		t.Errorf("default = %q", cfg.Default)
	}
	if cfg.Listen.Port != 3100 {
		t.Errorf("port = %d", cfg.Listen.Port)
	}
}
