package audit

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Entry represents a single audit log entry.
type Entry struct {
	Timestamp  time.Time `json:"ts"`
	Agent      string    `json:"agent"`
	Method     string    `json:"method"`
	Host       string    `json:"host"`
	Path       string    `json:"path"`
	Decision   string    `json:"decision"`
	Rule       string    `json:"rule"`
	Credential string    `json:"credential,omitempty"`
	StatusCode int       `json:"status_code,omitempty"`
	DurationMs int64     `json:"duration_ms"`
	RequestID  string    `json:"request_id"`
}

// Logger is the audit logging system.
type Logger struct {
	mu         sync.Mutex
	filePath   string
	maxDays    int
	buffer     []Entry
	bufferSize int
	bufferPos  int
	bufferFull bool
	file       *os.File
	currentDay string
}

// NewLogger creates an audit logger.
func NewLogger(filePath string, maxDays, bufferSize int) (*Logger, error) {
	l := &Logger{
		filePath:   filePath,
		maxDays:    maxDays,
		bufferSize: bufferSize,
		buffer:     make([]Entry, bufferSize),
	}
	if filePath != "" {
		if err := l.openFile(); err != nil {
			return nil, err
		}
	}
	return l, nil
}

func (l *Logger) openFile() error {
	dir := filepath.Dir(l.filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create audit dir: %w", err)
	}
	f, err := os.OpenFile(l.dailyPath(time.Now()), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("open audit file: %w", err)
	}
	l.file = f
	l.currentDay = time.Now().Format("2006-01-02")
	return nil
}

func (l *Logger) dailyPath(t time.Time) string {
	if l.filePath == "" {
		return ""
	}
	ext := filepath.Ext(l.filePath)
	base := strings.TrimSuffix(l.filePath, ext)
	day := t.Format("2006-01-02")
	if day == time.Now().Format("2006-01-02") {
		return l.filePath // current day uses the base path
	}
	return base + "." + day + ext
}

// Log records an audit entry.
func (l *Logger) Log(e Entry) {
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now()
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	// Ring buffer
	l.buffer[l.bufferPos] = e
	l.bufferPos = (l.bufferPos + 1) % l.bufferSize
	if l.bufferPos == 0 {
		l.bufferFull = true
	}

	// File rotation check
	if l.file != nil {
		day := e.Timestamp.Format("2006-01-02")
		if day != l.currentDay {
			l.file.Close()
			l.openFile()
			l.cleanOldFiles()
		}
	}

	// Write to file
	if l.file != nil {
		data, _ := json.Marshal(e)
		l.file.Write(append(data, '\n'))
	}
}

func (l *Logger) cleanOldFiles() {
	if l.maxDays <= 0 || l.filePath == "" {
		return
	}
	ext := filepath.Ext(l.filePath)
	base := strings.TrimSuffix(l.filePath, ext)
	cutoff := time.Now().AddDate(0, 0, -l.maxDays)

	dir := filepath.Dir(l.filePath)
	entries, _ := os.ReadDir(dir)
	for _, entry := range entries {
		name := entry.Name()
		fullBase := filepath.Base(base)
		if !strings.HasPrefix(name, fullBase+".") {
			continue
		}
		// Extract date from filename
		datePart := strings.TrimPrefix(name, fullBase+".")
		datePart = strings.TrimSuffix(datePart, ext)
		t, err := time.Parse("2006-01-02", datePart)
		if err != nil {
			continue
		}
		if t.Before(cutoff) {
			os.Remove(filepath.Join(dir, name))
		}
	}
}

// Recent returns the most recent entries from the ring buffer, optionally filtered.
func (l *Logger) Recent(limit int, agent string) []Entry {
	l.mu.Lock()
	defer l.mu.Unlock()

	var all []Entry
	if l.bufferFull {
		// Read from bufferPos to end, then 0 to bufferPos
		for i := l.bufferPos; i < l.bufferSize; i++ {
			all = append(all, l.buffer[i])
		}
		for i := 0; i < l.bufferPos; i++ {
			all = append(all, l.buffer[i])
		}
	} else {
		all = make([]Entry, l.bufferPos)
		copy(all, l.buffer[:l.bufferPos])
	}

	// Filter
	if agent != "" {
		var filtered []Entry
		for _, e := range all {
			if e.Agent == agent {
				filtered = append(filtered, e)
			}
		}
		all = filtered
	}

	// Return most recent (last N)
	if limit > 0 && limit < len(all) {
		all = all[len(all)-limit:]
	}
	return all
}

// Stats returns aggregate statistics.
type Stats struct {
	Total       int            `json:"total"`
	ByAgent     map[string]int `json:"by_agent"`
	ByDecision  map[string]int `json:"by_decision"`
	TopHosts    map[string]int `json:"top_hosts"`
}

func (l *Logger) Stats(since time.Duration) Stats {
	l.mu.Lock()
	defer l.mu.Unlock()

	cutoff := time.Time{}
	if since > 0 {
		cutoff = time.Now().Add(-since)
	}

	s := Stats{
		ByAgent:    make(map[string]int),
		ByDecision: make(map[string]int),
		TopHosts:   make(map[string]int),
	}

	iter := func(e Entry) {
		if !cutoff.IsZero() && e.Timestamp.Before(cutoff) {
			return
		}
		s.Total++
		s.ByAgent[e.Agent]++
		s.ByDecision[e.Decision]++
		s.TopHosts[e.Host]++
	}

	if l.bufferFull {
		for i := l.bufferPos; i < l.bufferSize; i++ {
			iter(l.buffer[i])
		}
		for i := 0; i < l.bufferPos; i++ {
			iter(l.buffer[i])
		}
	} else {
		for i := 0; i < l.bufferPos; i++ {
			iter(l.buffer[i])
		}
	}
	return s
}

// Close closes the audit file.
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file != nil {
		return l.file.Close()
	}
	return nil
}

// Handler returns an http.Handler for audit API routes.
func (l *Logger) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/audit/recent", l.handleRecent)
	mux.HandleFunc("/audit/stats", l.handleStats)
	return mux
}

func (l *Logger) handleRecent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	limit := 50
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	agent := r.URL.Query().Get("agent")
	entries := l.Recent(limit, agent)
	if entries == nil {
		entries = []Entry{}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(entries)
}

func (l *Logger) handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var since time.Duration
	if v := r.URL.Query().Get("since"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			since = d
		}
	}
	stats := l.Stats(since)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}
