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
	Decision             Decision
	Credential           string
	Rule                 string
	Service              string
	StripResponseHeaders []string
}

type Engine struct {
	cfg       *config.Config
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
				svc := rule.Service
					if svc == "" {
						svc = rule.Host
					}
					return Result{
					Decision:             AllowWithCredential,
					Credential:           rule.Credential,
					Rule:                 rule.Agent + " -> " + rule.Host + " " + method + " " + route.Path,
					Service:              svc,
					StripResponseHeaders: rule.StripResponseHeaders,
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

func pathMatches(pattern, reqPath string) bool {
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
			if len(pat) == 1 {
				return true
			}
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
		// * must not match empty string
		if p == "*" && req[0] == "" {
			return false
		}
		pat = pat[1:]
		req = req[1:]
	}
	// Handle trailing ** matching zero segments
	if len(req) == 0 {
		for _, p := range pat {
			if p != "**" {
				return false
			}
		}
		return true
	}
	return false
}
