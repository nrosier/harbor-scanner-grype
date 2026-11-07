package grype

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TechPrototyper/harbor-scanner-grype/pkg/harbor"
)

const tBound = 5 * time.Second

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

// fakeMgr scripts UpdateDB / DBStatus results.
type fakeMgr struct {
	mu        sync.Mutex
	updates   []error // consumed per UpdateDB call; empty -> nil
	calls     int
	block     chan struct{} // if set, UpdateDB waits for it or ctx
	called    chan struct{} // one send per UpdateDB entry
	ctxErr    chan error
	hasDB     bool
	built     time.Time
	statusErr error
}

func newMgr() *fakeMgr {
	return &fakeMgr{called: make(chan struct{}, 64), ctxErr: make(chan error, 64), built: time.Date(2026, 11, 7, 6, 0, 0, 0, time.UTC)}
}

func (m *fakeMgr) UpdateDB(ctx context.Context) error {
	m.mu.Lock()
	m.calls++
	var err error
	if len(m.updates) > 0 {
		err, m.updates = m.updates[0], m.updates[1:]
	}
	block := m.block
	if err == nil {
		m.hasDB = true
	}
	m.mu.Unlock()
	m.called <- struct{}{}
	if block != nil {
		select {
		case <-block:
		case <-ctx.Done():
			m.ctxErr <- ctx.Err()
			return ctx.Err()
		}
	}
	return err
}

func (m *fakeMgr) DBStatus(context.Context) (DBStatus, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.statusErr != nil {
		return DBStatus{}, m.statusErr
	}
	if !m.hasDB {
		return DBStatus{}, errors.New("database does not exist")
	}
	return DBStatus{Built: m.built, SchemaVersion: "v6.1.10"}, nil
}

// waitClock records requested delays; each Wait returns when tick delivers.
type waitClock struct {
	delays chan time.Duration
	tick   chan struct{}
}

func newWaitClock() *waitClock {
	return &waitClock{delays: make(chan time.Duration, 64), tick: make(chan struct{}, 64)}
}

func (c *waitClock) Wait(ctx context.Context, d time.Duration) error {
	c.delays <- d
	select {
	case <-c.tick:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func recv[T any](t *testing.T, ch <-chan T, what string) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(tBound):
		t.Fatalf("timeout waiting for %s", what)
		panic("unreachable")
	}
}

func startUpdater(t *testing.T, m *fakeMgr, c *waitClock, interval time.Duration, mut func(*DBUpdaterOptions)) (*DBUpdater, context.CancelFunc, chan struct{}) {
	t.Helper()
	o := DBUpdaterOptions{Manager: m, Interval: interval, Wait: c.Wait, Logger: quiet}
	if mut != nil {
		mut(&o)
	}
	u := NewDBUpdater(o)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); u.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done })
	return u, cancel, done
}

func eventually(t *testing.T, what string, f func() bool) {
	t.Helper()
	deadline := time.Now().Add(tBound)
	for !f() {
		if time.Now().After(deadline) {
			t.Fatalf("timeout waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestUpdaterRunsAtStartAndOnInterval(t *testing.T) {
	m, c := newMgr(), newWaitClock()
	var primed []time.Time
	var mu sync.Mutex
	u, _, _ := startUpdater(t, m, c, 24*time.Hour, func(o *DBUpdaterOptions) {
		o.OnUpdated = func(st DBStatus) { mu.Lock(); primed = append(primed, st.Built); mu.Unlock() }
	})
	recv(t, m.called, "startup update")
	if d := recv(t, c.delays, "interval wait"); d != 24*time.Hour {
		t.Fatalf("wait = %v, want 24h", d)
	}
	if !u.Ready() {
		t.Fatal("not ready after the first successful update")
	}
	c.tick <- struct{}{}
	recv(t, m.called, "second update")
	if d := recv(t, c.delays, "second interval wait"); d != 24*time.Hour {
		t.Fatalf("wait = %v, want 24h", d)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(primed) != 2 || !primed[1].Equal(m.built) {
		t.Fatalf("OnUpdated calls = %v, want 2 with the new build time", primed)
	}
}

func TestUpdaterIntervalZeroOnlyStartupUpdate(t *testing.T) {
	m, c := newMgr(), newWaitClock()
	u, _, done := startUpdater(t, m, c, 0, nil)
	recv(t, m.called, "startup update")
	recv(t, done, "Run to return") // returns after the startup update succeeded
	if !u.Ready() {
		t.Fatal("not ready")
	}
	if len(c.delays) != 0 || m.calls != 1 {
		t.Fatalf("periodic refresh ran: waits=%d calls=%d", len(c.delays), m.calls)
	}
}

func TestUpdaterIntervalZeroStillRetriesStartupFailure(t *testing.T) {
	m, c := newMgr(), newWaitClock()
	m.updates = []error{errors.New("offline")}
	u, _, done := startUpdater(t, m, c, 0, nil)
	recv(t, m.called, "first attempt")
	if d := recv(t, c.delays, "retry wait"); d != time.Minute {
		t.Fatalf("retry wait = %v, want 1m", d)
	}
	if u.Ready() {
		t.Fatal("ready without a DB")
	}
	c.tick <- struct{}{}
	recv(t, m.called, "retry")
	recv(t, done, "Run to return")
	if !u.Ready() {
		t.Fatal("not ready after the retry succeeded")
	}
}

func TestUpdaterBackoffDoublesAndCaps(t *testing.T) {
	m, c := newMgr(), newWaitClock()
	for i := 0; i < 9; i++ {
		m.updates = append(m.updates, errors.New("offline"))
	}
	startUpdater(t, m, c, 24*time.Hour, nil)
	want := []time.Duration{time.Minute, 2 * time.Minute, 4 * time.Minute, 8 * time.Minute, 16 * time.Minute, 32 * time.Minute, time.Hour, time.Hour, time.Hour}
	for i, w := range want {
		recv(t, m.called, "attempt")
		if d := recv(t, c.delays, "backoff"); d != w {
			t.Fatalf("backoff %d = %v, want %v", i, d, w)
		}
		c.tick <- struct{}{}
	}
	// success resets the backoff to the interval, then a new failure restarts at 1m
	recv(t, m.called, "successful attempt")
	if d := recv(t, c.delays, "interval"); d != 24*time.Hour {
		t.Fatalf("after success wait = %v, want 24h", d)
	}
	m.mu.Lock()
	m.updates = []error{errors.New("offline")}
	m.mu.Unlock()
	c.tick <- struct{}{}
	recv(t, m.called, "failing attempt")
	if d := recv(t, c.delays, "backoff after reset"); d != time.Minute {
		t.Fatalf("backoff after success = %v, want 1m", d)
	}
}

func TestUpdaterRetryNeverLaterThanInterval(t *testing.T) {
	m, c := newMgr(), newWaitClock()
	m.updates = []error{errors.New("offline")}
	startUpdater(t, m, c, 30*time.Second, nil)
	recv(t, m.called, "attempt")
	if d := recv(t, c.delays, "backoff"); d != 30*time.Second {
		t.Fatalf("retry wait = %v, want 30s (capped by the interval)", d)
	}
}

func TestUpdaterKeepsLastGoodDBOnFailure(t *testing.T) {
	m, c := newMgr(), newWaitClock()
	m.hasDB = true // a DB is already installed
	m.updates = []error{errors.New("offline")}
	u, _, _ := startUpdater(t, m, c, time.Hour, nil)
	recv(t, m.called, "failing update")
	recv(t, c.delays, "backoff")
	if !u.Ready() {
		t.Fatal("a failed refresh must not mark the existing DB unavailable")
	}
}

func TestUpdaterReadyImmediatelyWhenDBInstalled(t *testing.T) {
	m, c := newMgr(), newWaitClock()
	m.hasDB = true
	m.block = make(chan struct{}) // the startup refresh never finishes in this test
	u, _, _ := startUpdater(t, m, c, time.Hour, nil)
	recv(t, m.called, "update in flight")
	if !u.Ready() {
		t.Fatal("restart with an installed DB must be ready before the refresh finishes")
	}
}

func TestUpdaterNotReadyWithoutDB(t *testing.T) {
	m, c := newMgr(), newWaitClock()
	m.block = make(chan struct{})
	u, _, _ := startUpdater(t, m, c, time.Hour, nil)
	recv(t, m.called, "update in flight")
	if u.Ready() {
		t.Fatal("ready without a DB")
	}
	close(m.block)
	eventually(t, "ready after first update", u.Ready)
}

func TestUpdaterBrokenDBAfterSuccessfulCommandIsNotReady(t *testing.T) {
	m, c := newMgr(), newWaitClock()
	m.hasDB = true
	m.statusErr = errors.New("checksum mismatch")
	u, _, _ := startUpdater(t, m, c, time.Hour, nil)
	recv(t, m.called, "update")
	if d := recv(t, c.delays, "retry"); d != time.Minute {
		t.Fatalf("wait = %v, want the 1m failure backoff", d)
	}
	if u.Ready() {
		t.Fatal("an unusable DB must not be ready")
	}
}

func TestUpdaterShutdownCancelsInFlightUpdate(t *testing.T) {
	m, c := newMgr(), newWaitClock()
	m.block = make(chan struct{})
	_, cancel, done := startUpdater(t, m, c, time.Hour, nil)
	recv(t, m.called, "update in flight")
	cancel()
	if err := recv(t, m.ctxErr, "update ctx cancel"); !errors.Is(err, context.Canceled) {
		t.Fatalf("ctx err = %v", err)
	}
	recv(t, done, "Run to return")
}

func TestUpdaterBoundsEachUpdateWithTimeout(t *testing.T) {
	m, c := newMgr(), newWaitClock()
	m.block = make(chan struct{})
	startUpdater(t, m, c, time.Hour, func(o *DBUpdaterOptions) { o.Timeout = 20 * time.Millisecond })
	recv(t, m.called, "update")
	if err := recv(t, m.ctxErr, "timeout"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("ctx err = %v, want deadline exceeded", err)
	}
	if d := recv(t, c.delays, "backoff"); d != time.Minute {
		t.Fatalf("wait = %v", d)
	}
}

func TestUpdaterRemovesStaleDownloads(t *testing.T) {
	dir := t.TempDir()
	stale := filepath.Join(dir, "grype-db-download123")
	if err := os.MkdirAll(filepath.Join(stale, "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	keep := filepath.Join(dir, "6")
	if err := os.MkdirAll(keep, 0o700); err != nil {
		t.Fatal(err)
	}
	m, c := newMgr(), newWaitClock()
	startUpdater(t, m, c, time.Hour, func(o *DBUpdaterOptions) { o.CacheDir = dir })
	recv(t, m.called, "update")
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatalf("stale download not removed: %v", err)
	}
	if _, err := os.Stat(keep); err != nil {
		t.Fatalf("installed DB dir must stay: %v", err)
	}
}

// --- scan gate (RWMutex semantics) ---

type blockRunner struct {
	entered chan struct{}
	release chan struct{}
}

func (b *blockRunner) Scan(ctx context.Context, _ harbor.ScanRequest) (*Document, error) {
	b.entered <- struct{}{}
	select {
	case <-b.release:
		return &Document{}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
func (b *blockRunner) Version(context.Context) (string, time.Time, error) {
	return "", time.Time{}, nil
}

func TestUpdateWaitsForRunningScans(t *testing.T) {
	m, c := newMgr(), newWaitClock()
	m.hasDB = true
	br := &blockRunner{entered: make(chan struct{}, 4), release: make(chan struct{})}
	u := NewDBUpdater(DBUpdaterOptions{Manager: m, Interval: time.Hour, Wait: c.Wait, Logger: quiet})
	g := u.Guard(br)

	scanDone := make(chan error, 1)
	go func() { _, err := g.Scan(context.Background(), harbor.ScanRequest{}); scanDone <- err }()
	recv(t, br.entered, "scan start")

	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan struct{})
	go func() { defer close(runDone); u.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-runDone })

	select {
	case <-m.called:
		t.Fatal("update started while a scan was running")
	case <-time.After(100 * time.Millisecond):
	}
	close(br.release)
	if err := recv(t, scanDone, "scan finish"); err != nil {
		t.Fatal(err)
	}
	recv(t, m.called, "update after the scan finished")
}

func TestScansWaitDuringUpdate(t *testing.T) {
	m, c := newMgr(), newWaitClock()
	m.hasDB = true
	m.block = make(chan struct{})
	br := &blockRunner{entered: make(chan struct{}, 4), release: make(chan struct{})}
	close(br.release)
	u := NewDBUpdater(DBUpdaterOptions{Manager: m, Interval: time.Hour, Wait: c.Wait, Logger: quiet})
	g := u.Guard(br)
	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan struct{})
	go func() { defer close(runDone); u.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-runDone })
	recv(t, m.called, "update in flight")

	scanDone := make(chan error, 1)
	go func() { _, err := g.Scan(context.Background(), harbor.ScanRequest{}); scanDone <- err }()
	select {
	case <-br.entered:
		t.Fatal("scan started during an update")
	case <-time.After(100 * time.Millisecond):
	}
	close(m.block)
	recv(t, br.entered, "scan after the update")
	if err := recv(t, scanDone, "scan finish"); err != nil {
		t.Fatal(err)
	}
}

func TestQueuedScanIsCancellableWhileUpdateRuns(t *testing.T) {
	m, c := newMgr(), newWaitClock()
	m.hasDB = true
	m.block = make(chan struct{})
	br := &blockRunner{entered: make(chan struct{}, 4), release: make(chan struct{})}
	u := NewDBUpdater(DBUpdaterOptions{Manager: m, Interval: time.Hour, Wait: c.Wait, Logger: quiet})
	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan struct{})
	go func() { defer close(runDone); u.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-runDone })
	recv(t, m.called, "update in flight")

	sctx, scancel := context.WithCancel(context.Background())
	scanDone := make(chan error, 1)
	go func() { _, err := u.Guard(br).Scan(sctx, harbor.ScanRequest{}); scanDone <- err }()
	time.Sleep(20 * time.Millisecond)
	scancel()
	err := recv(t, scanDone, "queued scan to give up")
	if err == nil || PublicMessage(err, "") != "grype scan failed" {
		t.Fatalf("err = %v", err)
	}
}

func TestWaitingUpdateBlocksNewScans(t *testing.T) {
	var g scanGate
	g.wake = make(chan struct{})
	ctx := context.Background()
	if err := g.rlock(ctx); err != nil {
		t.Fatal(err)
	}
	locked := make(chan struct{})
	go func() { _ = g.lock(ctx); close(locked) }()
	eventually(t, "writer queued", func() bool { g.mu.Lock(); defer g.mu.Unlock(); return g.waiting == 1 })

	lateReader := make(chan struct{})
	go func() { _ = g.rlock(ctx); close(lateReader) }()
	select {
	case <-lateReader:
		t.Fatal("a new scan overtook the waiting update")
	case <-time.After(50 * time.Millisecond):
	}
	g.runlock()
	recv(t, locked, "writer")
	g.unlock()
	recv(t, lateReader, "late reader")
}

// --- CLI wiring ---

func TestCLIRunnerUpdateDB(t *testing.T) {
	fe := &fakeExec{}
	r := &CLIRunner{Opts: CLIOptions{Path: "grype"}, Exec: fe}
	if err := r.UpdateDB(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(fe.gotArgs, " "); got != "db update" {
		t.Fatalf("args = %q", got)
	}
}

func TestCLIRunnerDBStatus(t *testing.T) {
	fe := &fakeExec{stdout: []byte(`{"schemaVersion":"v6.1.10","built":"2026-11-07T06:18:48Z","valid":true}`)}
	r := &CLIRunner{Opts: CLIOptions{Path: "grype"}, Exec: fe}
	st, err := r.DBStatus(context.Background())
	if err != nil || !st.Built.Equal(time.Date(2026, 11, 7, 6, 18, 48, 0, time.UTC)) || st.SchemaVersion != "v6.1.10" {
		t.Fatalf("got %+v, %v", st, err)
	}
	if got := strings.Join(fe.gotArgs, " "); got != "db status -o json" {
		t.Fatalf("args = %q", got)
	}
	if !strings.Contains(strings.Join(fe.gotEnv, " "), EnvDBValidateHash+"=false") {
		t.Fatalf("status must skip hashing the DB: env %v", fe.gotEnv)
	}

	fe.stdout = []byte(`{"valid":false,"error":"database does not exist"}`)
	if _, err := r.DBStatus(context.Background()); err == nil {
		t.Fatal("invalid DB must be an error")
	}
	fe.stdout, fe.err = nil, errors.New("exit status 1")
	if _, err := r.DBStatus(context.Background()); err == nil {
		t.Fatal("non-zero exit must be an error")
	}
}

func TestScanMapsDBLoadFailureToPublicMessage(t *testing.T) {
	stderr := "run /usr/bin/grype: exit status 1: stderr: [0098] ERROR failed to load vulnerability db: database does not exist\n"
	fe := &fakeExec{err: errors.New(stderr)}
	r := &CLIRunner{Opts: CLIOptions{Path: "grype", Timeout: time.Minute}, Exec: fe}
	_, err := r.Scan(context.Background(), harbor.ScanRequest{
		Registry: harbor.Registry{URL: "https://harbor.example"},
		Artifact: harbor.Artifact{Repository: "lib/app", Digest: "sha256:0000"},
	})
	if err == nil {
		t.Fatal("expected an error")
	}
	if got := PublicMessage(err, "fallback"); got != MsgDBUnavailable {
		t.Fatalf("public = %q, want %q", got, MsgDBUnavailable)
	}
	if !strings.Contains(err.Error(), "failed to load vulnerability db") {
		t.Fatalf("the full error must stay available for logs: %v", err)
	}
	if MsgDBUnavailable != "vulnerability database not available" {
		t.Fatalf("public message changed: %q", MsgDBUnavailable)
	}
}
