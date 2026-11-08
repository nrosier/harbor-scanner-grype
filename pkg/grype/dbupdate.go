package grype

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/TechPrototyper/harbor-scanner-grype/pkg/harbor"
)

// Values chosen for this adapter (not taken from Grype).
const (
	// DefaultDBUpdateTimeout bounds one `grype db update` run. Grype's own
	// download timeout is 5m (GRYPE_DB_UPDATE_DOWNLOAD_TIMEOUT); this covers
	// the check, download, hydration and activation together.
	DefaultDBUpdateTimeout = 10 * time.Minute
	// dbStatusTimeout bounds one `grype db status` run.
	dbStatusTimeout = 2 * time.Minute
	// Failed updates are retried after dbRetryInitial, doubling up to dbRetryMax.
	dbRetryInitial = time.Minute
	dbRetryMax     = time.Hour
)

// MsgDBUnavailable is the stable public message for a vulnerability job that
// cannot run because there is no usable vulnerability database. It carries no
// stderr, paths or credentials, so it is safe to hand to Harbor.
const MsgDBUnavailable = "vulnerability database not available"

// grypeDBLoadFailure is the stderr text Grype v0.121.2 prints when the
// database cannot be loaded (cmd/grype/cli/commands/root.go, validateDBLoad).
const grypeDBLoadFailure = "failed to load vulnerability db"

// Grype writes a download into a "grype-db-download*" directory below the
// cache root (grype/db/v6/distribution/client.go Download) and only removes it
// on error it handles itself; a killed process leaves it behind.
const staleDownloadPrefix = "grype-db-download"

// Environment variables used for DB commands.
const (
	// EnvDBValidateHash makes `grype db status` skip hashing the multi-GB DB
	// file, so a status check is cheap. Scans still verify it on load.
	EnvDBValidateHash = "GRYPE_DB_VALIDATE_BY_HASH_ON_START"
)

// DBStatus is the state of the installed vulnerability database.
type DBStatus struct {
	Built         time.Time
	SchemaVersion string
}

// DBManager installs and inspects the vulnerability database.
type DBManager interface {
	// UpdateDB runs the equivalent of `grype db update`.
	UpdateDB(ctx context.Context) error
	// DBStatus returns the installed DB, or an error when there is no usable
	// DB (missing, unreadable, schema mismatch, older than Grype's maximum age).
	DBStatus(ctx context.Context) (DBStatus, error)
}

var _ DBManager = (*CLIRunner)(nil)

// UpdateDB runs `grype db update`. Grype downloads into a temporary directory
// and then swaps it in; see docs/ARCHITECTURE.md for why callers must keep
// scans away while it runs (DBUpdater does).
func (r *CLIRunner) UpdateDB(ctx context.Context) error {
	if _, err := r.Exec.Run(ctx, r.Opts.Path, []string{"db", "update"}, []string{EnvCheckAppUpdate + "=false"}); err != nil {
		return fmt.Errorf("grype db update: %w", err)
	}
	return nil
}

// dbStatusOutput is the subset of `grype db status -o json` we consume.
type dbStatusOutput struct {
	SchemaVersion string `json:"schemaVersion"`
	Built         string `json:"built"`
	Valid         bool   `json:"valid"`
	Error         string `json:"error"`
}

// DBStatus runs `grype db status -o json`. Grype exits non-zero when the DB is
// missing or invalid, which surfaces here as an error.
func (r *CLIRunner) DBStatus(ctx context.Context) (DBStatus, error) {
	out, err := r.Exec.Run(ctx, r.Opts.Path, []string{"db", "status", "-o", "json"},
		[]string{EnvCheckAppUpdate + "=false", EnvDBValidateHash + "=false"})
	if err != nil {
		return DBStatus{}, fmt.Errorf("grype db status: %w", err)
	}
	var so dbStatusOutput
	if err := json.Unmarshal(out, &so); err != nil {
		return DBStatus{}, fmt.Errorf("grype db status: decode output: %w", err)
	}
	if !so.Valid {
		return DBStatus{}, fmt.Errorf("grype db status: database invalid: %s", so.Error)
	}
	st := DBStatus{SchemaVersion: so.SchemaVersion}
	if t, err := time.Parse(time.RFC3339, so.Built); err == nil {
		st.Built = t
	}
	return st, nil
}

// DBState is the thread-safe "a usable vulnerability database exists" flag
// behind GET /readyz and the fail-fast check of vulnerability jobs.
type DBState struct{ ready atomic.Bool }

// Ready reports whether a usable database is available.
func (s *DBState) Ready() bool { return s.ready.Load() }

// Set records availability.
func (s *DBState) Set(ready bool) { s.ready.Store(ready) }

// DBUpdaterOptions configures NewDBUpdater. Zero fields get defaults.
type DBUpdaterOptions struct {
	Manager DBManager
	// Interval between successful refreshes. <= 0 disables periodic refresh;
	// the startup update still runs (and is retried until it succeeds).
	Interval time.Duration
	// Timeout bounds one update run; default DefaultDBUpdateTimeout.
	Timeout time.Duration
	// RetryInitial / RetryMax shape the failure backoff (default 1m, doubling
	// to 1h). A retry is never later than Interval when Interval > 0.
	RetryInitial, RetryMax time.Duration
	// Wait sleeps for d or returns ctx.Err(); tests inject a fake clock.
	// Default is a real timer.
	Wait func(ctx context.Context, d time.Duration) error
	// CacheDir, if set, is scanned at startup for download directories left by
	// an interrupted update (GRYPE_DB_CACHE_DIR).
	CacheDir string
	// OnUpdated runs after every successful update, with the DB now installed.
	OnUpdated func(DBStatus)
	// State receives availability changes; created when nil.
	State  *DBState
	Logger *slog.Logger
}

// DBUpdater keeps the vulnerability database present and fresh, and keeps
// scans and updates apart: Grype's update is not safe against concurrent
// readers (it deletes the live DB directory before moving the new one in),
// so scans (via Guard) share a gate that an update holds exclusively.
type DBUpdater struct {
	o    DBUpdaterOptions
	gate scanGate
}

// NewDBUpdater applies defaults.
func NewDBUpdater(o DBUpdaterOptions) *DBUpdater {
	if o.Timeout <= 0 {
		o.Timeout = DefaultDBUpdateTimeout
	}
	if o.RetryInitial <= 0 {
		o.RetryInitial = dbRetryInitial
	}
	if o.RetryMax < o.RetryInitial {
		o.RetryMax = max(dbRetryMax, o.RetryInitial)
	}
	if o.Wait == nil {
		o.Wait = sleepCtx
	}
	if o.State == nil {
		o.State = &DBState{}
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	u := &DBUpdater{o: o}
	u.gate.wake = make(chan struct{})
	return u
}

// Ready reports whether a usable database is available.
func (u *DBUpdater) Ready() bool { return u.o.State.Ready() }

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Run blocks until ctx is cancelled (or, with periodic refresh disabled, until
// the startup update has succeeded). It first records whether a usable DB is
// already installed (so a restart with a persistent volume is ready before the
// refresh finishes), then updates now and every Interval. A failed update is
// logged at WARN, the current DB is kept, and the retry backs off.
func (u *DBUpdater) Run(ctx context.Context) {
	u.removeStaleDownloads()
	u.refreshState(ctx)

	backoff := u.o.RetryInitial
	for {
		err := u.updateOnce(ctx)
		if ctx.Err() != nil {
			return
		}
		var delay time.Duration
		if err != nil {
			delay = backoff
			if u.o.Interval > 0 {
				delay = min(delay, u.o.Interval)
			}
			backoff = min(backoff*2, u.o.RetryMax)
			u.o.Logger.Warn("vulnerability DB update failed; keeping the current DB",
				"error", err.Error(), "retry_in", delay.String(), "db_available", u.Ready())
		} else {
			backoff = u.o.RetryInitial
			if u.o.Interval <= 0 {
				u.o.Logger.Info("periodic vulnerability DB refresh is disabled")
				return
			}
			delay = u.o.Interval
		}
		if u.o.Wait(ctx, delay) != nil {
			return
		}
	}
}

// updateOnce runs one update under the exclusive gate, then re-reads the DB
// status. A returned error means the update failed (the DB may still be usable).
func (u *DBUpdater) updateOnce(ctx context.Context) error {
	if err := u.gate.lock(ctx); err != nil {
		return err
	}
	uctx, cancel := context.WithTimeout(ctx, u.o.Timeout)
	u.o.Logger.Info("vulnerability DB update started")
	start := time.Now()
	err := u.o.Manager.UpdateDB(uctx)
	cancel()
	u.gate.unlock()
	if ctx.Err() != nil {
		return ctx.Err() // shutting down: leave the state as it is
	}
	st, serr := u.status(ctx)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if serr != nil {
		u.o.State.Set(false)
		u.o.Logger.Warn("vulnerability DB not usable", "error", serr.Error())
		if err == nil {
			return fmt.Errorf("check DB after update: %w", serr)
		}
		return err
	}
	u.o.State.Set(true)
	if err != nil {
		return err
	}
	u.o.Logger.Info("vulnerability DB up to date", "built", st.Built.UTC().Format(time.RFC3339),
		"schema", st.SchemaVersion, "duration", time.Since(start).String())
	if u.o.OnUpdated != nil {
		u.o.OnUpdated(st)
	}
	return nil
}

// refreshState sets the availability from the installed DB.
func (u *DBUpdater) refreshState(ctx context.Context) {
	st, err := u.status(ctx)
	if ctx.Err() != nil {
		return
	}
	if err != nil {
		u.o.State.Set(false)
		u.o.Logger.Info("no usable vulnerability DB installed yet", "error", err.Error())
		return
	}
	u.o.State.Set(true)
	u.o.Logger.Info("vulnerability DB found", "built", st.Built.UTC().Format(time.RFC3339), "schema", st.SchemaVersion)
	if u.o.OnUpdated != nil {
		u.o.OnUpdated(st)
	}
}

func (u *DBUpdater) status(ctx context.Context) (DBStatus, error) {
	sctx, cancel := context.WithTimeout(ctx, dbStatusTimeout)
	defer cancel()
	return u.o.Manager.DBStatus(sctx)
}

// removeStaleDownloads deletes download directories a killed `grype db
// update` left in the cache root. Only the updater runs updates and it has
// not started one yet, so no live download can be hit.
func (u *DBUpdater) removeStaleDownloads() {
	if u.o.CacheDir == "" {
		return
	}
	entries, err := os.ReadDir(u.o.CacheDir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !e.IsDir() || !strings.HasPrefix(e.Name(), staleDownloadPrefix) {
			continue
		}
		p := filepath.Join(u.o.CacheDir, e.Name())
		if err := os.RemoveAll(p); err != nil {
			u.o.Logger.Warn("could not remove stale DB download", "path", p, "error", err.Error())
			continue
		}
		u.o.Logger.Info("removed stale DB download", "path", p)
	}
}

// Guard wraps r so every Scan holds the shared side of the gate: a scan
// waits while an update runs, and an update waits for running scans.
func (u *DBUpdater) Guard(r Runner) Runner { return guardedRunner{Runner: r, gate: &u.gate} }

type guardedRunner struct {
	Runner
	gate *scanGate
}

func (g guardedRunner) Scan(ctx context.Context, req harbor.ScanRequest) (*Document, error) {
	if err := g.gate.rlock(ctx); err != nil {
		return nil, &Failure{Public: "grype scan failed", Err: fmt.Errorf("wait for vulnerability DB update: %w", err)}
	}
	defer g.gate.runlock()
	return g.Runner.Scan(ctx, req)
}

// scanGate is a context-aware reader/writer lock: scans are readers, an
// update is the single writer. A waiting writer blocks new readers (so an
// update is not starved by a stream of scans). sync.RWMutex cannot be used
// directly because a scan queued behind a long download must still be
// cancellable on shutdown.
type scanGate struct {
	mu      sync.Mutex
	readers int
	writing bool
	waiting int           // writers waiting
	wake    chan struct{} // closed and replaced on every state change
}

// broadcast must be called with mu held.
func (g *scanGate) broadcast() {
	close(g.wake)
	g.wake = make(chan struct{})
}

func (g *scanGate) rlock(ctx context.Context) error {
	g.mu.Lock()
	for g.writing || g.waiting > 0 {
		w := g.wake
		g.mu.Unlock()
		select {
		case <-w:
		case <-ctx.Done():
			return ctx.Err()
		}
		g.mu.Lock()
	}
	g.readers++
	g.mu.Unlock()
	return nil
}

func (g *scanGate) runlock() {
	g.mu.Lock()
	g.readers--
	if g.readers == 0 {
		g.broadcast()
	}
	g.mu.Unlock()
}

func (g *scanGate) lock(ctx context.Context) error {
	g.mu.Lock()
	g.waiting++
	for g.writing || g.readers > 0 {
		w := g.wake
		g.mu.Unlock()
		select {
		case <-w:
		case <-ctx.Done():
			g.mu.Lock()
			g.waiting--
			g.broadcast()
			g.mu.Unlock()
			return ctx.Err()
		}
		g.mu.Lock()
	}
	g.waiting--
	g.writing = true
	g.mu.Unlock()
	return nil
}

func (g *scanGate) unlock() {
	g.mu.Lock()
	g.writing = false
	g.broadcast()
	g.mu.Unlock()
}

// isDBLoadFailure reports whether err carries Grype's "failed to load
// vulnerability db" stderr.
func isDBLoadFailure(err error) bool {
	return err != nil && !errors.Is(err, context.Canceled) && strings.Contains(err.Error(), grypeDBLoadFailure)
}
