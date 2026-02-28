package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/skarard/openclaw-auth-proxy/internal/config"
)

// CredentialStore resolves credentials at startup into memory.
type CredentialStore struct {
	values map[string]string
}

func NewCredentialStore(creds map[string]config.Cred) (*CredentialStore, error) {
	store := &CredentialStore{values: make(map[string]string, len(creds))}
	for key, cred := range creds {
		val, err := resolve(cred)
		if err != nil {
			return nil, fmt.Errorf("credential %q: %w", key, err)
		}
		store.values[key] = val
	}
	return store, nil
}

func (s *CredentialStore) Get(key string) (string, bool) {
	v, ok := s.values[key]
	return v, ok
}

func resolve(cred config.Cred) (string, error) {
	switch cred.Source {
	case "env":
		return resolveEnv(cred)
	case "file":
		return resolveFile(cred)
	case "exec":
		return resolveExec(cred)
	default:
		return "", fmt.Errorf("unknown source %q", cred.Source)
	}
}

func resolveEnv(cred config.Cred) (string, error) {
	val := os.Getenv(cred.ID)
	if val == "" {
		return "", fmt.Errorf("env var %s is empty or not set", cred.ID)
	}
	return val, nil
}

func resolveFile(cred config.Cred) (string, error) {
	data, err := os.ReadFile(cred.Path)
	if err != nil {
		return "", fmt.Errorf("read file %s: %w", cred.Path, err)
	}

	var root interface{}
	if err := json.Unmarshal(data, &root); err != nil {
		return "", fmt.Errorf("parse JSON from %s: %w", cred.Path, err)
	}

	val, err := jsonPointerResolve(root, cred.ID)
	if err != nil {
		return "", fmt.Errorf("resolve pointer %q in %s: %w", cred.ID, cred.Path, err)
	}
	return val, nil
}

// jsonPointerResolve resolves an RFC 6901 JSON pointer against a parsed JSON value.
func jsonPointerResolve(root interface{}, pointer string) (string, error) {
	if pointer == "" || pointer == "/" {
		return "", fmt.Errorf("empty pointer")
	}
	if !strings.HasPrefix(pointer, "/") {
		return "", fmt.Errorf("pointer must start with /")
	}

	parts := strings.Split(pointer[1:], "/")
	current := root

	for _, part := range parts {
		// RFC 6901 unescaping
		part = strings.ReplaceAll(part, "~1", "/")
		part = strings.ReplaceAll(part, "~0", "~")

		obj, ok := current.(map[string]interface{})
		if !ok {
			return "", fmt.Errorf("expected object at %q, got %T", part, current)
		}
		current, ok = obj[part]
		if !ok {
			return "", fmt.Errorf("key %q not found", part)
		}
	}

	switch v := current.(type) {
	case string:
		return v, nil
	case float64:
		return fmt.Sprintf("%g", v), nil
	case bool:
		return fmt.Sprintf("%t", v), nil
	default:
		return "", fmt.Errorf("value at pointer is %T, not a scalar", current)
	}
}

type execRequest struct {
	ProtocolVersion int      `json:"protocolVersion"`
	Provider        string   `json:"provider"`
	IDs             []string `json:"ids"`
}

type execResponse struct {
	ProtocolVersion int               `json:"protocolVersion"`
	Values          map[string]string `json:"values"`
	Errors          map[string]string `json:"errors"`
}

// ExecTimeout is the timeout for exec credential resolution. Exported for testing.
var ExecTimeout = 30 * time.Second

func resolveExec(cred config.Cred) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), ExecTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, cred.Command, cred.Args...)

	reqData, err := json.Marshal(execRequest{
		ProtocolVersion: 1,
		Provider:        cred.Command,
		IDs:             []string{cred.ID},
	})
	if err != nil {
		return "", fmt.Errorf("marshal exec request: %w", err)
	}

	cmd.Stdin = bytes.NewReader(reqData)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("exec %s failed: %w (stderr: %s)", cred.Command, err, stderr.String())
	}

	var resp execResponse
	if err := json.Unmarshal(stdout.Bytes(), &resp); err != nil {
		return "", fmt.Errorf("parse exec response: %w", err)
	}

	if errMsg, ok := resp.Errors[cred.ID]; ok {
		return "", fmt.Errorf("exec returned error for %q: %s", cred.ID, errMsg)
	}

	val, ok := resp.Values[cred.ID]
	if !ok {
		return "", fmt.Errorf("exec response missing value for %q", cred.ID)
	}
	return val, nil
}
