package main

import (
	"crypto/sha256"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"

	"github.com/skarard/openclaw-auth-proxy/internal/config"
	"github.com/skarard/openclaw-auth-proxy/internal/policy"
	"github.com/skarard/openclaw-auth-proxy/internal/proxy"
)

func main() {
	configPath := flag.String("config", "proxy.config.yaml", "path to config file")
	generateCA := flag.Bool("generate-ca", false, "generate CA certificate and exit")
	certDir := flag.String("cert-dir", "/etc/auth-proxy/certs/", "directory for CA certificate output")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	if *generateCA {
		if err := runGenerateCA(*certDir, logger); err != nil {
			logger.Error("failed to generate CA", "error", err)
			os.Exit(1)
		}
		return
	}

	cfg, err := config.LoadAuto(*configPath)
	if err != nil {
		logger.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	logger.Info("config loaded",
		"agents", len(cfg.Agents),
		"rules", len(cfg.Rules),
		"default", cfg.Default,
		"upstreams", len(cfg.Upstreams),
	)

	creds, err := proxy.NewCredentialStore(cfg.Credentials)
	if err != nil {
		logger.Error("failed to resolve credentials", "error", err)
		os.Exit(1)
	}
	logger.Info("credentials resolved", "count", len(cfg.Credentials))

	engine := policy.NewEngine(cfg)
	p := proxy.New(engine, creds, logger, cfg.Logging.Audit)

	// Setup TLS MITM if enabled
	if cfg.TLS.Enabled {
		cm, err := setupTLS(cfg.TLS, logger)
		if err != nil {
			logger.Error("failed to setup TLS", "error", err)
			os.Exit(1)
		}
		p.SetCertManager(cm)
		logger.Info("TLS MITM interception enabled")
	}

	// Start upstream listeners
	if len(cfg.Upstreams) > 0 {
		listeners, err := proxy.StartUpstreamListeners(cfg.Upstreams, engine, creds, logger, cfg.Logging.Audit)
		if err != nil {
			logger.Error("failed to start upstream listeners", "error", err)
			os.Exit(1)
		}
		defer func() {
			for _, l := range listeners {
				l.Close()
			}
		}()
	}

	addr := cfg.Listen.Addr()
	logger.Info("starting auth proxy", "addr", addr)

	server := &http.Server{
		Addr:    addr,
		Handler: p,
	}

	if err := server.ListenAndServe(); err != nil {
		fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		os.Exit(1)
	}
}

func setupTLS(tlsCfg config.TLS, logger *slog.Logger) (*proxy.CertManager, error) {
	var certPEM, keyPEM []byte

	if tlsCfg.CACert != "" && tlsCfg.CAKey != "" {
		// Load from files
		var err error
		certPEM, err = os.ReadFile(tlsCfg.CACert)
		if err != nil {
			return nil, fmt.Errorf("read CA cert: %w", err)
		}
		keyPEM, err = os.ReadFile(tlsCfg.CAKey)
		if err != nil {
			return nil, fmt.Errorf("read CA key: %w", err)
		}
		logger.Info("loaded CA from files", "cert", tlsCfg.CACert, "key", tlsCfg.CAKey)
	} else if tlsCfg.AutoGen {
		certDir := tlsCfg.CertDir
		if certDir == "" {
			certDir = "/etc/auth-proxy/certs/"
		}
		certPath := filepath.Join(certDir, "ca.crt")
		keyPath := filepath.Join(certDir, "ca.key")

		// Check if already exists
		if _, err := os.Stat(certPath); err == nil {
			certPEM, _ = os.ReadFile(certPath)
			keyPEM, _ = os.ReadFile(keyPath)
			logger.Info("loaded existing auto-generated CA", "dir", certDir)
		} else {
			// Generate new
			var err error
			certPEM, keyPEM, err = proxy.GenerateCA()
			if err != nil {
				return nil, fmt.Errorf("generate CA: %w", err)
			}
			os.MkdirAll(certDir, 0700)
			if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
				return nil, fmt.Errorf("write CA cert: %w", err)
			}
			if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
				return nil, fmt.Errorf("write CA key: %w", err)
			}
			logger.Info("generated new CA", "dir", certDir)
		}
	} else {
		return nil, fmt.Errorf("TLS enabled but no CA configured (set ca_cert/ca_key or auto_gen)")
	}

	// Log fingerprint
	hash := sha256.Sum256(certPEM)
	logger.Info("CA certificate fingerprint", "sha256", fmt.Sprintf("%x", hash))

	return proxy.NewCertManager(certPEM, keyPEM)
}

func runGenerateCA(certDir string, logger *slog.Logger) error {
	certPEM, keyPEM, err := proxy.GenerateCA()
	if err != nil {
		return err
	}

	if err := os.MkdirAll(certDir, 0700); err != nil {
		return fmt.Errorf("create cert dir: %w", err)
	}

	certPath := filepath.Join(certDir, "ca.crt")
	keyPath := filepath.Join(certDir, "ca.key")

	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		return fmt.Errorf("write CA cert: %w", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return fmt.Errorf("write CA key: %w", err)
	}

	hash := sha256.Sum256(certPEM)
	logger.Info("CA generated",
		"cert", certPath,
		"key", keyPath,
		"fingerprint", fmt.Sprintf("%x", hash),
	)
	fmt.Printf("CA certificate: %s\n", certPath)
	fmt.Printf("CA private key: %s\n", keyPath)
	fmt.Println("\nTo trust in agent containers:")
	fmt.Println("  COPY ca.crt /usr/local/share/ca-certificates/auth-proxy-ca.crt")
	fmt.Println("  RUN update-ca-certificates")

	return nil
}
