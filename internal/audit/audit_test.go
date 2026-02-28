package audit

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLogAndRingBuffer(t *testing.T) {
	dir := t.TempDir()
	l, err := NewLogger(filepath.Join(dir, "audit.jsonl"), 7, 5)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	for i := 0; i < 3; i++ {
		l.Log(Entry{Agent: "pa", Method: "GET", Host: "api.github.com", Decision: "allow", RequestID: "r" + string(rune('0'+i))})
	}

	recent := l.Recent(10, "")
	if len(recent) != 3 {
		t.Errorf("recent = %d, want 3", len(recent))
	}
}

func TestRingBufferOverflow(t *testing.T) {
	l, _ := NewLogger("", 0, 3)

	for i := 0; i < 5; i++ {
		l.Log(Entry{Agent: "pa", RequestID: string(rune('A' + i))})
	}

	recent := l.Recent(10, "")
	if len(recent) != 3 {
		t.Errorf("recent = %d, want 3", len(recent))
	}
}

func TestFilterByAgent(t *testing.T) {
	l, _ := NewLogger("", 0, 100)
	l.Log(Entry{Agent: "pa", Decision: "allow"})
	l.Log(Entry{Agent: "tc", Decision: "deny"})
	l.Log(Entry{Agent: "pa", Decision: "deny"})

	recent := l.Recent(100, "pa")
	if len(recent) != 2 {
		t.Errorf("filtered = %d, want 2", len(recent))
	}
}

func TestStats(t *testing.T) {
	l, _ := NewLogger("", 0, 100)
	l.Log(Entry{Agent: "pa", Decision: "allow", Host: "api.github.com", Timestamp: time.Now()})
	l.Log(Entry{Agent: "pa", Decision: "deny", Host: "api.github.com", Timestamp: time.Now()})
	l.Log(Entry{Agent: "tc", Decision: "allow", Host: "api.vercel.com", Timestamp: time.Now()})

	s := l.Stats(0)
	if s.Total != 3 {
		t.Errorf("total = %d", s.Total)
	}
	if s.ByAgent["pa"] != 2 {
		t.Errorf("pa = %d", s.ByAgent["pa"])
	}
	if s.ByDecision["allow"] != 2 {
		t.Errorf("allow = %d", s.ByDecision["allow"])
	}
	if s.TopHosts["api.github.com"] != 2 {
		t.Errorf("github = %d", s.TopHosts["api.github.com"])
	}
}

func TestFileWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	l, err := NewLogger(path, 7, 100)
	if err != nil {
		t.Fatal(err)
	}
	l.Log(Entry{Agent: "pa", Decision: "allow"})
	l.Close()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 1 {
		t.Errorf("lines = %d", len(lines))
	}
	var e Entry
	json.Unmarshal([]byte(lines[0]), &e)
	if e.Agent != "pa" {
		t.Errorf("agent = %q", e.Agent)
	}
}

func TestHTTPRecent(t *testing.T) {
	l, _ := NewLogger("", 0, 100)
	l.Log(Entry{Agent: "pa", Decision: "allow"})

	h := l.Handler()
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/audit/recent?limit=10", nil)
	h.ServeHTTP(w, r)

	if w.Code != 200 {
		t.Fatalf("status = %d", w.Code)
	}
	var entries []Entry
	json.Unmarshal(w.Body.Bytes(), &entries)
	if len(entries) != 1 {
		t.Errorf("entries = %d", len(entries))
	}
}

func TestHTTPStats(t *testing.T) {
	l, _ := NewLogger("", 0, 100)
	l.Log(Entry{Agent: "pa", Decision: "allow", Timestamp: time.Now()})

	h := l.Handler()
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/audit/stats", nil)
	h.ServeHTTP(w, r)

	if w.Code != 200 {
		t.Fatalf("status = %d", w.Code)
	}
	var s Stats
	json.Unmarshal(w.Body.Bytes(), &s)
	if s.Total != 1 {
		t.Errorf("total = %d", s.Total)
	}
}
