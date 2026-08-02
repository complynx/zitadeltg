package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/complynx/zitadeltg/internal/app"
)

func main() {
	configPath := flag.String("config", "config.yaml", "path to YAML config")
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	cfg, err := app.LoadConfig(*configPath)
	if err != nil {
		logger.Error("load config failed", slog.String("config", *configPath), slog.Any("error", err))
		os.Exit(1)
	}

	signer, err := app.NewSigner(cfg.JWT)
	if err != nil {
		logger.Error("load JWT signer failed", slog.Any("error", err))
		os.Exit(1)
	}
	if signer.Ephemeral() {
		logger.Warn("using ephemeral JWT signing key; configure jwt.private_key_file or jwt.private_key for stable ZITADEL verification")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	server, err := app.NewServer(ctx, cfg, signer, &http.Client{Timeout: 10 * time.Second}, logger)
	if err != nil {
		logger.Error("create server failed", slog.Any("error", err))
		os.Exit(1)
	}
	httpServer := &http.Server{
		Addr:              cfg.Listen,
		Handler:           server,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 * 1024,
	}

	logger.Info("zitadeltg listening", slog.String("addr", cfg.Listen), slog.String("issuer", cfg.Issuer), slog.Int("bot_count", len(cfg.Bots)))
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- httpServer.ListenAndServe()
	}()

	select {
	case err := <-serveErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server stopped", slog.Any("error", err))
			os.Exit(1)
		}
	case <-ctx.Done():
		logger.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			logger.Error("graceful shutdown failed", slog.Any("error", err))
			os.Exit(1)
		}
	}
}
