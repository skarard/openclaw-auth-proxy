package admin

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/skarard/openclaw-auth-proxy/internal/config"
)

// Server is the admin HTTP server.
type Server struct {
	mux     *http.ServeMux
	cfg     *config.Config
}

// NewServer creates an admin server with the given sub-handlers.
func NewServer(cfg *config.Config, authHandler http.Handler, auditHandler http.Handler) *Server {
	s := &Server{
		mux: http.NewServeMux(),
		cfg: cfg,
	}

	s.mux.HandleFunc("/health", s.handleHealth)
	s.mux.HandleFunc("/config", s.handleConfig)
	s.mux.HandleFunc("/agents", s.handleAgents)

	if authHandler != nil {
		s.mux.Handle("/auth/", authHandler)
	}
	if auditHandler != nil {
		s.mux.Handle("/audit/", auditHandler)
	}

	return s
}

// Handler returns the http.Handler for the admin server.
func (s *Server) Handler() http.Handler {
	return s.mux
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// Redact credentials
	type redactedCred struct {
		Source string `json:"source"`
		ID     string `json:"id,omitempty"`
	}
	redacted := make(map[string]redactedCred, len(s.cfg.Credentials))
	for k, c := range s.cfg.Credentials {
		redacted[k] = redactedCred{Source: c.Source, ID: c.ID}
	}

	out := map[string]interface{}{
		"listen":      s.cfg.Listen,
		"logging":     s.cfg.Logging,
		"default":     s.cfg.Default,
		"credentials": redacted,
		"agents":      s.cfg.Agents,
		"rules_count": len(s.cfg.Rules),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

// AgentSummary is a summary of an agent's access.
type AgentSummary struct {
	IP       string   `json:"ip"`
	Services []string `json:"services"`
}

func (s *Server) handleAgents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	summaries := make(map[string]AgentSummary, len(s.cfg.Agents))
	for name, agent := range s.cfg.Agents {
		summary := AgentSummary{IP: agent.IP}
		// Collect hosts from rules
		seen := map[string]bool{}
		for _, rule := range s.cfg.Rules {
			if rule.Agent == name && !seen[rule.Host] {
				seen[rule.Host] = true
				summary.Services = append(summary.Services, rule.Host)
			}
		}
		if summary.Services == nil {
			summary.Services = []string{}
		}
		summaries[name] = summary
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(summaries)
}

// StripPrefix returns a handler that strips a prefix and delegates.
// This is a simple helper since we need prefix-based routing.
func StripPrefix(prefix string, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, prefix) {
			h.ServeHTTP(w, r)
		} else {
			http.NotFound(w, r)
		}
	})
}
