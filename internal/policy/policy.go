package policy

import (
	"path"
	"strings"

	"github.com/skarard/openclaw-auth-proxy/internal/config"
)

type Decision int

const (
	Deny Decision = iota
	Allow
	AllowWithCredential
)

type Result struct {
	Decision   Decision
	Credential string // credential key if AllowWithCredential
	Rule       string // description for audit log
}

type Engine struct {
	cfg *config.Config
	// reverse lookup: IP -> agent ID
	ipToAgent map[string]string
}

func NewEngine(cfg *config.Config) *Engine {
	ipMap := make(map[string]string, len(cfg.Agents))
	for id, a := range cfg.Agents {
		ipMap[a.IP] = id
	}
	return &Engine{cfg: cfg, ipToAgent: ipMap}
}

func (e *Engine) AgentForIP(ip string) (string, bool) {
	// Strip port if present
	if idx := strings.LastIndex(ip, ":"); idx != -1 {
		ip = ip[:idx]
	}
	agent, ok := e.ipToAgent[ip]
	return agent, ok
}

func (e *Engine) Evaluate(agent, method, host, reqPath string) Result {
	for _, rule := range e.cfg.Rules {
		if rule.Agent != agent || rule.Host != host {
			continue
		}
		for _, route := range rule.Routes {
			if !methodMatches(route.Methods(), method) {
				continue
			}
			if pathMatches(route.Path, reqPath) {
				return Result{
					Decision:   AllowWithCredential,
					Credential: rule.Credential,
					Rule:       rule.Agent + " -> " + rule.Host + " " + method + " " + route.Path,
				}
			}
		}
	}
	if e.cfg.Default == "passthrough" {
		return Result{Decision: Allow, Rule: "default:passthrough"}
	}
	return Result{Decision: Deny, Rule: "default:deny"}
}

func methodMatches(allowed []string, method string) bool {
	if len(allowed) == 0 {
		return true
	}
	method = strings.ToUpper(method)
	for _, m := range allowed {
		if strings.ToUpper(m) == method {
			return true
		}
	}
	return false
}

// pathMatches supports * (single segment) and ** (any depth).
func pathMatches(pattern, reqPath string) bool {
	// Normalise
	pattern = path.Clean("/" + pattern)
	reqPath = path.Clean("/" + reqPath)

	patParts := strings.Split(pattern, "/")
	reqParts := strings.Split(reqPath, "/")

	return matchParts(patParts, reqParts)
}

func matchParts(pat, req []string) bool {
	for len(pat) > 0 && len(req) > 0 {
		p := pat[0]
		if p == "**" {
			// ** at the end matches everything
			if len(pat) == 1 {
				return true
			}
			// Try matching remaining pattern at every position
			for i := 0; i <= len(req); i++ {
				if matchParts(pat[1:], req[i:]) {
					return true
				}
			}
			return false
		}
		if p != "*" && p != req[0] {
			return false
		}
		pat = pat[1:]
		req = req[1:]
	}
	return len(pat) == 0 && len(req) == 0
}
