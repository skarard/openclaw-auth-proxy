package authflow

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNewRequest(t *testing.T) {
	m := NewManager(5*time.Minute, "", nil)
	ar, isNew := m.Request("pa", "github", "api.github.com", "GET", "/repos")
	if !isNew {
		t.Error("expected new request")
	}
	if ar.Status != "pending" {
		t.Errorf("status = %q", ar.Status)
	}
	if ar.Agent != "pa" {
		t.Errorf("agent = %q", ar.Agent)
	}
}

func TestDeduplication(t *testing.T) {
	m := NewManager(5*time.Minute, "", nil)
	ar1, _ := m.Request("pa", "github", "api.github.com", "GET", "/repos")
	ar2, isNew := m.Request("pa", "github", "api.github.com", "POST", "/other")
	if isNew {
		t.Error("expected dedup")
	}
	if ar1.ID != ar2.ID {
		t.Error("should return same request")
	}
}

func TestDedupDifferentAgents(t *testing.T) {
	m := NewManager(5*time.Minute, "", nil)
	m.Request("pa", "github", "api.github.com", "GET", "/repos")
	_, isNew := m.Request("tc", "github", "api.github.com", "GET", "/repos")
	if !isNew {
		t.Error("different agent should not dedup")
	}
}

func TestWebhook(t *testing.T) {
	var received *AuthRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var ar AuthRequest
		json.NewDecoder(r.Body).Decode(&ar)
		received = &ar
		w.WriteHeader(200)
	}))
	defer srv.Close()

	m := NewManager(5*time.Minute, srv.URL, nil)
	m.Request("pa", "github", "api.github.com", "GET", "/repos")

	// Wait for async webhook
	time.Sleep(100 * time.Millisecond)
	if received == nil {
		t.Fatal("webhook not called")
	}
	if received.Agent != "pa" {
		t.Errorf("webhook agent = %q", received.Agent)
	}
}

func TestApprove(t *testing.T) {
	var setKey, setVal string
	m := NewManager(5*time.Minute, "", func(k, v string) {
		setKey = k
		setVal = v
	})
	ar, _ := m.Request("pa", "github", "api.github.com", "GET", "/repos")
	if err := m.Approve(ar.ID, "token123"); err != nil {
		t.Fatal(err)
	}
	if setKey != "pa-github" || setVal != "token123" {
		t.Errorf("setCred(%q, %q)", setKey, setVal)
	}
	if ar.Status != "approved" {
		t.Errorf("status = %q", ar.Status)
	}
}

func TestDeny(t *testing.T) {
	m := NewManager(5*time.Minute, "", nil)
	ar, _ := m.Request("pa", "github", "api.github.com", "GET", "/repos")
	if err := m.Deny(ar.ID); err != nil {
		t.Fatal(err)
	}
	if ar.Status != "denied" {
		t.Errorf("status = %q", ar.Status)
	}
}

func TestPendingFilter(t *testing.T) {
	m := NewManager(5*time.Minute, "", nil)
	m.Request("pa", "github", "api.github.com", "GET", "/repos")
	ar2, _ := m.Request("tc", "github", "api.vercel.com", "GET", "/deployments")
	m.Deny(ar2.ID)

	pending := m.Pending()
	if len(pending) != 1 {
		t.Errorf("pending = %d, want 1", len(pending))
	}
}

func TestHistory(t *testing.T) {
	m := NewManager(5*time.Minute, "", nil)
	m.Request("pa", "github", "api.github.com", "GET", "/repos")
	m.Request("tc", "github", "api.vercel.com", "GET", "/deployments")
	hist := m.History()
	if len(hist) != 2 {
		t.Errorf("history = %d, want 2", len(hist))
	}
}

func TestHTTPPending(t *testing.T) {
	m := NewManager(5*time.Minute, "", nil)
	m.Request("pa", "github", "api.github.com", "GET", "/repos")

	h := m.Handler()
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/auth/pending", nil)
	h.ServeHTTP(w, r)

	if w.Code != 200 {
		t.Fatalf("status = %d", w.Code)
	}
	var list []AuthRequest
	json.Unmarshal(w.Body.Bytes(), &list)
	if len(list) != 1 {
		t.Errorf("got %d pending", len(list))
	}
}

func TestHTTPApprove(t *testing.T) {
	m := NewManager(5*time.Minute, "", func(k, v string) {})
	ar, _ := m.Request("pa", "github", "api.github.com", "GET", "/repos")

	h := m.Handler()
	w := httptest.NewRecorder()
	body := `{"credential":"tok"}`
	r := httptest.NewRequest("POST", "/auth/"+ar.ID+"/approve", strings.NewReader(body))
	h.ServeHTTP(w, r)

	if w.Code != 200 {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
}

func TestHTTPDeny(t *testing.T) {
	m := NewManager(5*time.Minute, "", nil)
	ar, _ := m.Request("pa", "github", "api.github.com", "GET", "/repos")

	h := m.Handler()
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/auth/"+ar.ID+"/deny", nil)
	h.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("status = %d", w.Code)
	}
}

func TestHTTPHistory(t *testing.T) {
	m := NewManager(5*time.Minute, "", nil)
	m.Request("pa", "github", "api.github.com", "GET", "/repos")

	h := m.Handler()
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/auth/history", nil)
	h.ServeHTTP(w, r)

	body, _ := io.ReadAll(w.Body)
	var list []AuthRequest
	json.Unmarshal(body, &list)
	if len(list) != 1 {
		t.Errorf("history = %d", len(list))
	}
}
