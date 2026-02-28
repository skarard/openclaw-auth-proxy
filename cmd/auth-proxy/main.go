package main

import (
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"github.com/skarard/openclaw-auth-proxy/internal/config"
	"github.com/skarard/openclaw-auth-proxy/internal/policy"
	"github.com/skarard/openclaw-auth-proxy/internal/proxy"
)

func main() {
	configPath := flag.String("config", "proxy.config.yaml", "path to config file")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	cfg, err := config.Load(*configPath)
	if err != nil {
		logger.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	logger.Info("config loaded",
		"agents", len(cfg.Agents),
		"rules", len(cfg.Rules),
		"default", cfg.Default,
	)

	// Resolve all credentials at startup
	creds, err := proxy.NewCredentialStore(cfg.Credentials)
	if err != nil {
		logger.Error("failed to resolve credentials", "error", err)
		os.Exit(1)
	}
	logger.Info("credentials resolved", "count", len(cfg.Credentials))

	engine := policy.NewEngine(cfg)
	p := proxy.New(engine, creds, logger, cfg.Logging.Audit)

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
