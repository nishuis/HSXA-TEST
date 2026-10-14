// Command bfp-server serves the offline banner fingerprinting API.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"hsxa-banner-fingerprint/internal/api"
	"hsxa-banner-fingerprint/internal/config"
	"hsxa-banner-fingerprint/internal/engine"
	"hsxa-banner-fingerprint/internal/rules"
	"hsxa-banner-fingerprint/internal/version"
)

// Exit codes of bfp-server.
const (
	exitOK      = 0
	exitFailure = 1
	exitUsage   = 2
	exitUnready = 3
)

func main() {
	os.Exit(run(os.Args[1:], os.Getenv))
}

func run(args []string, getenv func(string) string) int {
	cfg, err := config.LoadServer(args, getenv)
	if err != nil {
		fmt.Fprintln(os.Stderr, "bfp-server:", err)
		return exitUsage
	}
	if cfg.ShowVersion {
		fmt.Println("bfp-server", version.String())
		return exitOK
	}
	if cfg.HealthCheck {
		return healthCheck(cfg)
	}

	logger := newLogger(cfg.LogLevel)

	registry, err := rules.Builtin()
	if err != nil {
		logger.Error("load built-in rules", "error", err)
		return exitFailure
	}
	if cfg.RulesDir != "" {
		if err := rules.LoadOverlays(registry, cfg.RulesDir); err != nil {
			// Fail fast: a broken overlay must never be served (plan.md §4.3).
			logger.Error("load external rule overlays", "dir", cfg.RulesDir, "error", err)
			return exitFailure
		}
	}
	eng := engine.New(registry)
	logger.Info("rules loaded",
		"version", version.Version,
		"protocols", len(registry.Protocols()),
		"rules", registry.RuleCount(),
		"rules_dir", cfg.RulesDir,
	)

	srv := api.New(eng, api.Options{
		MaxBodyBytes:   cfg.MaxBody,
		MaxRecords:     cfg.MaxRecords,
		MaxBannerBytes: cfg.MaxBannerBytes,
		Logger:         logger,
		StartedAt:      time.Now(),
	})
	httpSrv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       cfg.ReadTimeout,
		WriteTimeout:      cfg.WriteTimeout,
		IdleTimeout:       cfg.IdleTimeout,
	}

	srv.SetReady(true)
	errCh := make(chan error, 1)
	go func() {
		logger.Info("listening", "addr", cfg.ListenAddr)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	select {
	case err := <-errCh:
		logger.Error("serve", "error", err)
		return exitFailure
	case sig := <-signals:
		logger.Info("shutting down", "signal", sig.String())
	}
	ctx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownGrace)
	defer cancel()
	if err := httpSrv.Shutdown(ctx); err != nil {
		logger.Error("graceful shutdown", "error", err)
		return exitFailure
	}
	return exitOK
}

// healthCheck probes the local server so the container image needs no curl.
func healthCheck(cfg *config.Server) int {
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(cfg.HealthCheckURL)
	if err != nil {
		fmt.Fprintln(os.Stderr, "bfp-server: health check failed:", err)
		return exitUnready
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "bfp-server: health check got %s\n", resp.Status)
		return exitUnready
	}
	fmt.Println("ok")
	return exitOK
}

func newLogger(level string) *slog.Logger {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: lvl}))
}
