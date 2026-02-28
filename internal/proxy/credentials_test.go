package proxy

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/skarard/openclaw-auth-proxy/internal/config"
)

func TestEnvSource(t *testing.T) {
	os.Setenv("TEST_CRED_ABC", "secret123")
	defer os.Unsetenv("TEST_CRED_ABC")

	store, err := NewCredentialStore(map[string]config.Cred{
		"test": {Source: "env", ID: "TEST_CRED_ABC"},
	})
	if err != nil {
		t.Fatal(err)
	}
	val, ok := store.Get("test")
	if !ok || val != "secret123" {
		t.Errorf("got %q ok=%v", val, ok)
	}
}

func TestEnvSourceMissing(t *testing.T) {
	os.Unsetenv("TEST_CRED_MISSING")
	_, err := NewCredentialStore(map[string]config.Cred{
		"test": {Source: "env", ID: "TEST_CRED_MISSING"},
	})
	if err == nil {
		t.Fatal("expected error for missing env var")
	}
}

func TestFileSource(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "creds.json")
	os.WriteFile(p, []byte(`{"github":{"pa":{"token":"ghp_abc123"}}}`), 0644)

	store, err := NewCredentialStore(map[string]config.Cred{
		"gh": {Source: "file", Path: p, ID: "/github/pa/token"},
	})
	if err != nil {
		t.Fatal(err)
	}
	val, ok := store.Get("gh")
	if !ok || val != "ghp_abc123" {
		t.Errorf("got %q ok=%v", val, ok)
	}
}

func TestFileSourceNested(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "creds.json")
	os.WriteFile(p, []byte(`{"a":{"b":{"c":{"d":"deep"}}}}`), 0644)

	store, err := NewCredentialStore(map[string]config.Cred{
		"x": {Source: "file", Path: p, ID: "/a/b/c/d"},
	})
	if err != nil {
		t.Fatal(err)
	}
	val, _ := store.Get("x")
	if val != "deep" {
		t.Errorf("got %q", val)
	}
}

func TestFileSourceMissingFile(t *testing.T) {
	_, err := NewCredentialStore(map[string]config.Cred{
		"x": {Source: "file", Path: "/nonexistent/file.json", ID: "/key"},
	})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestFileSourceInvalidPointer(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "creds.json")
	os.WriteFile(p, []byte(`{"a":"b"}`), 0644)

	_, err := NewCredentialStore(map[string]config.Cred{
		"x": {Source: "file", Path: p, ID: "/nonexistent/key"},
	})
	if err == nil {
		t.Fatal("expected error for invalid pointer")
	}
}

func TestExecSource(t *testing.T) {
	// Create a mock resolver script
	dir := t.TempDir()
	script := filepath.Join(dir, "resolver.sh")
	os.WriteFile(script, []byte(`#!/bin/sh
read input
echo '{"protocolVersion":1,"values":{"my/secret":"sk-test123"}}'
`), 0755)

	store, err := NewCredentialStore(map[string]config.Cred{
		"x": {Source: "exec", Command: script, ID: "my/secret"},
	})
	if err != nil {
		t.Fatal(err)
	}
	val, ok := store.Get("x")
	if !ok || val != "sk-test123" {
		t.Errorf("got %q ok=%v", val, ok)
	}
}

func TestExecSourceError(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "fail.sh")
	os.WriteFile(script, []byte("#!/bin/sh\nexit 1\n"), 0755)

	_, err := NewCredentialStore(map[string]config.Cred{
		"x": {Source: "exec", Command: script, ID: "key"},
	})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestExecSourcePerIDError(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "resolver.sh")
	os.WriteFile(script, []byte(`#!/bin/sh
read input
echo '{"protocolVersion":1,"values":{},"errors":{"my/key":"not found"}}'
`), 0755)

	_, err := NewCredentialStore(map[string]config.Cred{
		"x": {Source: "exec", Command: script, ID: "my/key"},
	})
	if err == nil {
		t.Fatal("expected error for per-id error")
	}
}

func TestExecSourceTimeout(t *testing.T) {
	oldTimeout := ExecTimeout
	ExecTimeout = 100 * time.Millisecond
	defer func() { ExecTimeout = oldTimeout }()

	dir := t.TempDir()
	script := filepath.Join(dir, "slow.sh")
	os.WriteFile(script, []byte("#!/bin/sh\nsleep 10\n"), 0755)

	_, err := NewCredentialStore(map[string]config.Cred{
		"x": {Source: "exec", Command: script, ID: "key"},
	})
	if err == nil {
		t.Fatal("expected timeout error")
	}
}

func TestUnknownSource(t *testing.T) {
	_, err := NewCredentialStore(map[string]config.Cred{
		"x": {Source: "vault", ID: "key"},
	})
	if err == nil {
		t.Fatal("expected error for unknown source")
	}
}
