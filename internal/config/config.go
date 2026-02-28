package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Agents      map[string]Agent `yaml:"agents"`
	Credentials map[string]Cred  `yaml:"credentials"`
	Rules       []Rule           `yaml:"rules"`
	Default     string           `yaml:"default"` // "deny" or "passthrough"
	Listen      Listen           `yaml:"listen"`
	Logging     Logging          `yaml:"logging"`
	Upstreams   []Upstream       `yaml:"upstreams"`
}

type Agent struct {
	IP string `yaml:"ip"`
}

type Cred struct {
	Source  string   `yaml:"source"`  // "env", "file", "exec"
	ID      string   `yaml:"id"`
	Path    string   `yaml:"path"`    // file source: path to JSON file
	Command string   `yaml:"command"` // exec source: binary path
	Args    []string `yaml:"args"`    // exec source: arguments
}

type Rule struct {
	Agent      string  `yaml:"agent"`
	Host       string  `yaml:"host"`
	Credential string  `yaml:"credential"`
	Routes     []Route `yaml:"routes"`
}

type Route struct {
	Method interface{} `yaml:"method"` // string or []string
	Path   string      `yaml:"path"`
}

func (r Route) Methods() []string {
	switch v := r.Method.(type) {
	case string:
		return []string{v}
	case []interface{}:
		out := make([]string, 0, len(v))
		for _, m := range v {
			if s, ok := m.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

type Listen struct {
	Host string `yaml:"host"`
	Port int    `yaml:"port"`
}

func (l Listen) Addr() string {
	return fmt.Sprintf("%s:%d", l.Host, l.Port)
}

type Logging struct {
	Level string `yaml:"level"`
	Audit bool   `yaml:"audit"`
}

type Upstream struct {
	Name       string `yaml:"name"`
	ListenPort int    `yaml:"listen_port"`
	Target     string `yaml:"target"` // e.g. https://api.github.com
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if cfg.Default == "" {
		cfg.Default = "deny"
	}
	if cfg.Listen.Port == 0 {
		cfg.Listen.Port = 3100
	}
	if cfg.Listen.Host == "" {
		cfg.Listen.Host = "0.0.0.0"
	}
	return &cfg, nil
}
