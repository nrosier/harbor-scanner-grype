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

// HTTP server timeouts. These are values chosen for this adapter, not
// taken from any standard.
const (
	// readHeaderTimeout guards against slowloris-style clients.
	readHeaderTimeout = 10 * time.Second
	// readTimeout bounds reading the whole request; Harbor's request body
	// is capped at 1 MiB.
	readTimeout = 30 * time.Second
	// writeTimeout bounds writing the response; the largest response is an
	// SPDX SBOM document, and report 302 responses return immediately
	// (no long-poll).
	writeTimeout = 60 * time.Second
	// idleTimeout bounds keep-alive idle time; Harbor reuses connections.
	idleTimeout = 120 * time.Second

	// dbTimestampTTL bounds how stale the /metadata vulnerability-database
	// timestamp can be when grype auto-updates its DB. /metadata polling is
	// infrequent, and the TTL bounds how often grype is forked to read it.
	dbTimestampTTL = 5 * time.Minute
)

// Shutdown budgets. These are values chosen for this adapter. Worst case is
// scanDrainTimeout + the 5s post-cancel grace inside api.Server.Shutdown +
// httpShutdownTimeout = 35s, which must fit inside the chart's
// terminationGracePeriodSeconds (default 45) with a margin.
const (
	// scanDrainTimeout bounds how long in-flight scans may finish after a
	// shutdown signal before they are cancelled.
	scanDrainTimeout = 25 * time.Second
	// httpShutdownTimeout bounds finishing in-flight HTTP responses once
	// scans are drained.
	httpShutdownTimeout = 5 * time.Second
	// updaterStopTimeout bounds the wait for the cancelled DB updater (its
	// child process is killed on cancel; WaitDelay is 5s).
	updaterStopTimeout = 6 * time.Second
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == healthcheckCommand {
		os.Exit(runHealthcheck(os.Getenv, os.Stdout, os.Stderr))
	}
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

	sbomGen := grype.NewSyftRunner(grype.SyftOptions{
		Path:            cfg.SyftPath,
		Timeout:         cfg.ScanTimeout,
		InsecureSkipTLS: cfg.InsecureSkipTLS,
		UseHTTP:         cfg.UseHTTP,
	})

	scanner := harbor.Scanner{Name: "Grype", Vendor: "Anchore"}
	// The DB build time is not part of `grype version -o json` in v0.112.0;
	// the updater reads it from `grype db status` and logs it.
	version, _, err := runner.Version(context.Background())
	if err != nil {
		logger.Warn("grype version unavailable", "error", err.Error())
	} else {
		scanner.Version = version
		logger.Info("grype ready", "version", version)
	}

	// The scanner version is read once above; only the DB timestamp is
	// refreshed (TTL-cached) so /metadata follows DB updates. The build time
	// comes from `grype db status` ("grype version -o json" has no DB section
	// in v0.112.0).
	dbCache := grype.NewDBTimeCache(grype.DBTimeCacheOptions{
		Fetch: func(ctx context.Context) (time.Time, error) {
			st, err := runner.DBStatus(ctx)
			return st.Built, err
		},
		TTL:    dbTimestampTTL,
		Logger: logger,
	})

	// The updater downloads the DB at startup and refreshes it periodically,
	// off the HTTP path; /readyz reports 503 until a DB is available. Scans
	// are guarded so an update never replaces the DB under a running scan.
	updater := grype.NewDBUpdater(grype.DBUpdaterOptions{
		Manager:   runner,
		Interval:  cfg.DBUpdateInterval,
		CacheDir:  os.Getenv("GRYPE_DB_CACHE_DIR"),
		OnUpdated: func(st grype.DBStatus) { dbCache.Prime(st.Built) },
		Logger:    logger,
	})
	updaterCtx, stopUpdater := context.WithCancel(context.Background())
	defer stopUpdater()
	updaterDone := make(chan struct{})
	go func() { defer close(updaterDone); updater.Run(updaterCtx) }()

	apiServer := api.New(api.Options{
		Scanner:       scanner,
		RefreshAfter:  15,
		DBUpdatedAt:   dbCache.Get,
		DBReady:       updater.Ready,
		MapperOptions: grype.MapperOptions{PreferCVE: cfg.PreferCVE},
		Logger:        logger,

		WorkerConcurrency: cfg.WorkerConcurrency,
	}, store, updater.Guard(runner), sbomGen)

	stopCleanup := make(chan struct{})
	if cfg.JobTTL > 0 && cfg.CleanupInterval > 0 {
		go runCleanupTicker(cfg.CleanupInterval, func() int { return store.Cleanup(cfg.JobTTL) }, logger, stopCleanup)
	}

	server := &http.Server{
		Addr:              cfg.Addr,
		Handler:           apiServer,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
	}
	errCh := make(chan error, 1)
	go func() { errCh <- server.ListenAndServe() }()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	select {
	case <-ctx.Done():
		logger.Info("shutdown signal received")
		close(stopCleanup)
		// Cancel an in-flight DB update first: it holds the scan gate, and
		// scans queued behind it would otherwise miss the drain budget.
		stopUpdater()
		// Drain scans first: the closing flag makes new POSTs return 503 while
		// the HTTP listener keeps serving GET /report, /metadata and probes,
		// so Harbor can still collect results of scans being drained.
		drainCtx, cancelDrain := context.WithTimeout(context.Background(), scanDrainTimeout)
		defer cancelDrain()
		if err := apiServer.Shutdown(drainCtx); err != nil {
			logger.Warn("scans did not finish before the shutdown deadline; interrupted", "error", err.Error())
		}
		// Then stop the listener with its own short budget so in-flight HTTP
		// responses can finish.
		httpCtx, cancelHTTP := context.WithTimeout(context.Background(), httpShutdownTimeout)
		defer cancelHTTP()
		if err := server.Shutdown(httpCtx); err != nil {
			logger.Error("graceful shutdown failed; forcing close", "error", err.Error())
			_ = server.Close()
		}
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server error", "error", err.Error())
			os.Exit(1)
		}
	}
	stopUpdater()
	select {
	case <-updaterDone:
	case <-time.After(updaterStopTimeout):
		logger.Warn("DB updater did not stop in time")
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
// It returns when stop is closed.
func runCleanupTicker(interval time.Duration, cleanup func() int, log *slog.Logger, stop <-chan struct{}) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			if removed := cleanup(); removed > 0 {
				log.Info("cleaned up jobs", "removed", removed)
			}
		}
	}
}
