package proxy

import (
	"fmt"
	"os"

	"github.com/skarard/openclaw-auth-proxy/internal/config"
)

// CredentialStore resolves credentials at startup into memory.
type CredentialStore struct {
	values map[string]string // credential key -> resolved value
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
		val := os.Getenv(cred.ID)
		if val == "" {
			return "", fmt.Errorf("env var %s is empty or not set", cred.ID)
		}
		return val, nil
	case "file", "exec":
		// TODO: implement file (JSON pointer) and exec (stdin/stdout protocol)
		return "", fmt.Errorf("source %q not yet implemented", cred.Source)
	default:
		return "", fmt.Errorf("unknown source %q", cred.Source)
	}
}
