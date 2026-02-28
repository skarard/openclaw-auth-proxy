package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// V2Config represents the v2 configuration format with per-agent service definitions.
type V2Config struct {
	Version     int                `yaml:"version"`
	Listen      Listen             `yaml:"listen"`
	Logging     Logging            `yaml:"logging"`
	Credentials map[string]Cred    `yaml:"credentials"`
	Agents      map[string]V2Agent `yaml:"agents"`
	Default     string             `yaml:"default"`
	AuthFlow    AuthFlowConfig     `yaml:"authflow"`
	Audit       AuditConfig        `yaml:"audit"`
	TLS         TLS                `yaml:"tls"`
}

type V2Agent struct {
	IP       string               `yaml:"ip"`
	Services map[string]V2Service `yaml:"services"`
}

type V2Service struct {
	Host                 string   `yaml:"host"`
	Credential           string   `yaml:"credential"`
	StripResponseHeaders []string `yaml:"strip_response_headers"`
	Routes               []Route  `yaml:"routes"`
}

// AuthFlowConfig configures the reactive auth flow system.
type AuthFlowConfig struct {
	Enabled    bool   `yaml:"enabled"`
	AdminPort  int    `yaml:"admin_port"`
	WebhookURL string `yaml:"webhook_url"`
	Cooldown   string `yaml:"cooldown"`
}

// AuditConfig configures the audit logging system.
type AuditConfig struct {
	Enabled    bool          `yaml:"enabled"`
	File       string        `yaml:"file"`
	Rotation   AuditRotation `yaml:"rotation"`
	BufferSize int           `yaml:"buffer_size"`
}

type AuditRotation struct {
	MaxDays int `yaml:"max_days"`
}

type versionProbe struct {
	Version int `yaml:"version"`
}

// LoadAuto loads a config file, auto-detecting v1 or v2 format.
func LoadAuto(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	return ParseAuto(data)
}

// ParseAuto parses config data, auto-detecting v1 or v2 format.
func ParseAuto(data []byte) (*Config, error) {
	var probe versionProbe
	if err := yaml.Unmarshal(data, &probe); err != nil {
		return nil, fmt.Errorf("parse config version: %w", err)
	}
	if probe.Version == 2 {
		return parseV2(data)
	}
	return parseV1(data)
}

func parseV1(data []byte) (*Config, error) {
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	applyDefaults(&cfg)
	return &cfg, nil
}

func parseV2(data []byte) (*Config, error) {
	var v2 V2Config
	if err := yaml.Unmarshal(data, &v2); err != nil {
		return nil, fmt.Errorf("parse v2 config: %w", err)
	}
	return normalizeV2(&v2)
}

func normalizeV2(v2 *V2Config) (*Config, error) {
	cfg := &Config{
		Listen:      v2.Listen,
		Logging:     v2.Logging,
		Credentials: v2.Credentials,
		Default:     v2.Default,
		TLS:         v2.TLS,
		Agents:      make(map[string]Agent, len(v2.Agents)),
	}

	for agentName, v2agent := range v2.Agents {
		cfg.Agents[agentName] = Agent{IP: v2agent.IP}
		for svcName, svc := range v2agent.Services {
			rule := Rule{
				Agent:                agentName,
				Host:                 svc.Host,
				Credential:           svc.Credential,
				Service:              svcName,
				StripResponseHeaders: svc.StripResponseHeaders,
				Routes:               svc.Routes,
			}
			cfg.Rules = append(cfg.Rules, rule)
		}
	}

	applyDefaults(cfg)
	return cfg, nil
}

func applyDefaults(cfg *Config) {
	if cfg.Default == "" {
		cfg.Default = "deny"
	}
	if cfg.Listen.Port == 0 {
		cfg.Listen.Port = 3100
	}
	if cfg.Listen.Host == "" {
		cfg.Listen.Host = "0.0.0.0"
	}
}
