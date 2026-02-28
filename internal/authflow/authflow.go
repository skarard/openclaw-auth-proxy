package authflow

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

// AuthRequest represents a pending authentication request.
type AuthRequest struct {
	ID        string    `json:"id"`
	Agent     string    `json:"agent"`
	Service   string    `json:"service"`
	Host      string    `json:"host"`
	Method    string    `json:"method"`
	Path      string    `json:"path"`
	Timestamp time.Time `json:"timestamp"`
	Status    string    `json:"status"`
}

// CredentialSetter is called when an auth request is approved.
type CredentialSetter func(key, value string)

// Manager handles auth flow requests.
type Manager struct {
	mu          sync.Mutex
	requests    map[string]*AuthRequest
	history     []*AuthRequest
	cooldown    time.Duration
	webhookURL  string
	setCred     CredentialSetter
	httpClient  *http.Client
}

// NewManager creates a new auth flow manager.
func NewManager(cooldown time.Duration, webhookURL string, setCred CredentialSetter) *Manager {
	return &Manager{
		requests:   make(map[string]*AuthRequest),
		cooldown:   cooldown,
		webhookURL: webhookURL,
		setCred:    setCred,
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
}

func generateID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// Request creates or deduplicates an auth request. Returns the request and whether it's new.
func (m *Manager) Request(agent, service, host, method, path string) (*AuthRequest, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Deduplicate by agent+host within cooldown
	dedupKey := agent + ":" + host
	for _, req := range m.requests {
		if req.Status == "pending" && req.Agent+":"+req.Host == dedupKey {
			if time.Since(req.Timestamp) < m.cooldown {
				return req, false
			}
		}
	}

	ar := &AuthRequest{
		ID:        generateID(),
		Agent:     agent,
		Service:   service,
		Host:      host,
		Method:    method,
		Path:      path,
		Timestamp: time.Now(),
		Status:    "pending",
	}
	m.requests[ar.ID] = ar
	m.history = append(m.history, ar)

	// Fire webhook async
	if m.webhookURL != "" {
		go m.fireWebhook(ar)
	}

	log.Printf("[authflow] new auth request id=%s agent=%s host=%s", ar.ID, agent, host)
	return ar, true
}

func (m *Manager) fireWebhook(ar *AuthRequest) {
	data, _ := json.Marshal(ar)
	resp, err := m.httpClient.Post(m.webhookURL, "application/json", bytes.NewReader(data))
	if err != nil {
		log.Printf("[authflow] webhook error: %v", err)
		return
	}
	resp.Body.Close()
}

// Approve approves an auth request with the given credential value.
func (m *Manager) Approve(id, credentialValue string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	ar, ok := m.requests[id]
	if !ok {
		return fmt.Errorf("auth request %q not found", id)
	}
	if ar.Status != "pending" {
		return fmt.Errorf("auth request %q is %s, not pending", id, ar.Status)
	}
	ar.Status = "approved"

	if m.setCred != nil {
		// Use agent+host as credential key
		m.setCred(ar.Agent+"-"+ar.Service, credentialValue)
	}
	return nil
}

// Deny denies an auth request.
func (m *Manager) Deny(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	ar, ok := m.requests[id]
	if !ok {
		return fmt.Errorf("auth request %q not found", id)
	}
	if ar.Status != "pending" {
		return fmt.Errorf("auth request %q is %s, not pending", id, ar.Status)
	}
	ar.Status = "denied"
	return nil
}

// Pending returns all pending requests.
func (m *Manager) Pending() []*AuthRequest {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*AuthRequest
	for _, ar := range m.requests {
		if ar.Status == "pending" {
			out = append(out, ar)
		}
	}
	return out
}

// History returns all auth requests.
func (m *Manager) History() []*AuthRequest {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]*AuthRequest, len(m.history))
	copy(cp, m.history)
	return cp
}

// Handler returns an http.Handler for auth flow API routes.
func (m *Manager) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/auth/pending", m.handlePending)
	mux.HandleFunc("/auth/history", m.handleHistory)
	mux.HandleFunc("/auth/", m.handleAction)
	return mux
}

func (m *Manager) handlePending(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	pending := m.Pending()
	if pending == nil {
		pending = []*AuthRequest{}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(pending)
}

func (m *Manager) handleHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	hist := m.History()
	if hist == nil {
		hist = []*AuthRequest{}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(hist)
}

func (m *Manager) handleAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// Parse /auth/{id}/approve or /auth/{id}/deny
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) != 3 || parts[0] != "auth" {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	id := parts[1]
	action := parts[2]

	switch action {
	case "approve":
		var body struct {
			Credential string `json:"credential"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if err := m.Approve(id, body.Credential); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"status":"approved"}`)
	case "deny":
		if err := m.Deny(id); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"status":"denied"}`)
	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
}
