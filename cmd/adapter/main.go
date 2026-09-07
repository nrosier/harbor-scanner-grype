// Command adapter serves the Harbor Pluggable Scanner Adapter API backed
// by the Grype CLI.
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

	"github.com/TechPrototyper/harbor-scanner-grype/internal/config"
	"github.com/TechPrototyper/harbor-scanner-grype/pkg/api"
	"github.com/TechPrototyper/harbor-scanner-grype/pkg/grype"
	"github.com/TechPrototyper/harbor-scanner-grype/pkg/harbor"
	"github.com/TechPrototyper/harbor-scanner-grype/pkg/job"
)

func main() {
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config: %v\n", err)
		os.Exit(1)
	}

	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel(cfg.LogLevel)}))
	logger.Info("starting", "addr", cfg.Addr, "grype", cfg.GrypePath, "log_level", cfg.LogLevel)

	store := job.NewMemoryStore()
	runner := grype.NewCLIRunner(grype.CLIOptions{
		Path:            cfg.GrypePath,
		Timeout:         cfg.ScanTimeout,
		InsecureSkipTLS: cfg.InsecureSkipTLS,
		UseHTTP:         cfg.UseHTTP,
		DBAutoUpdate:    cfg.DBAutoUpdate,
	})

	scanner := harbor.Scanner{Name: "Grype", Vendor: "Anchore"}
	version, dbBuilt, err := runner.Version(context.Background())
	if err != nil {
		logger.Warn("grype version unavailable", "error", err.Error())
	} else {
		scanner.Version = version
		logger.Info("grype ready", "version", version, "db_built_at", dbBuilt.UTC().Format(time.RFC3339))
	}

	var dbUpdatedAt func() time.Time
	if !dbBuilt.IsZero() {
		dbUpdatedAt = func() time.Time { return dbBuilt }
	}

	handler := api.New(api.Options{
		Scanner:       scanner,
		RefreshAfter:  15,
		DBUpdatedAt:   dbUpdatedAt,
		MapperOptions: grype.MapperOptions{PreferCVE: cfg.PreferCVE},
		Logger:        logger,
	}, store, runner)

	if cfg.JobTTL > 0 && cfg.CleanupInterval > 0 {
		go runCleanupTicker(cfg.CleanupInterval, func() int { return store.Cleanup(cfg.JobTTL) }, logger)
	}

	server := &http.Server{Addr: cfg.Addr, Handler: handler}
	errCh := make(chan error, 1)
	go func() { errCh <- server.ListenAndServe() }()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	select {
	case <-ctx.Done():
		logger.Info("shutdown signal received")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			logger.Error("graceful shutdown failed; forcing close", "error", err.Error())
			_ = server.Close()
		}
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server error", "error", err.Error())
			os.Exit(1)
		}
	}
	logger.Info("stopped")
}

// logLevel maps SCANNER_LOG_LEVEL (validated by config) to a slog level.
func logLevel(level string) slog.Level {
	switch level {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// runCleanupTicker removes expired Finished/Failed jobs every interval.
func runCleanupTicker(interval time.Duration, cleanup func() int, log *slog.Logger) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		if removed := cleanup(); removed > 0 {
			log.Info("cleaned up jobs", "removed", removed)
		}
	}
}
