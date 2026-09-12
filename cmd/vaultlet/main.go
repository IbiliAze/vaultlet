package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/IbiliAze/vaultlet/internal/adapters/driven/azure"
	"github.com/IbiliAze/vaultlet/internal/adapters/driven/bitwarden"
	"github.com/IbiliAze/vaultlet/internal/adapters/driving/grpcserver"
	service "github.com/IbiliAze/vaultlet/internal/app"
	"github.com/IbiliAze/vaultlet/internal/config"
	"github.com/IbiliAze/vaultlet/internal/ports"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))

	if err := run(); err != nil {
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("validate config: %w", err)
	}

	store, err := newStore(cfg)
	if err != nil {
		return fmt.Errorf("open backend %q: %w", cfg.Backend, err)
	}
	if closer, ok := store.(interface{ Close() }); ok {
		defer closer.Close()
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var specs []service.RuleSpec
	for _, user := range cfg.Auth.Users {
		for _, rule := range user.Allow {
			specs = append(specs, service.RuleSpec{
				Principal: user.Username,
				Namespace: rule.Namespace,
				Actions:   rule.Actions,
			})
		}
	}

	policy, err := service.NewPolicy(specs)
	if err != nil {
		return fmt.Errorf("policy initialisation: %w", err)
	}

	app := service.NewService(store, policy)
	server, err := grpcserver.New(app, cfg.TLS, cfg.Auth)
	if err != nil {
		return fmt.Errorf("server initialisation: %w", err)
	}

	if err := server.Listen(ctx, cfg.Listen); err != nil {
		return fmt.Errorf("listen %q: %w", cfg.Listen, err)
	}
	return nil
}

func newStore(cfg config.Config) (ports.SecretStore, error) {
	switch cfg.Backend {
	case "bitwarden":
		return bitwarden.New(cfg.Bitwarden)
	case "azure":
		return azure.New(cfg.Azure)
	default:
		return nil, fmt.Errorf("unknown backend %q", cfg.Backend)
	}
}
