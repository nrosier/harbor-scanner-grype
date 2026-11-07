package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TechPrototyper/harbor-scanner-grype/pkg/grype"
	"github.com/TechPrototyper/harbor-scanner-grype/pkg/harbor"
	"github.com/TechPrototyper/harbor-scanner-grype/pkg/job"
)

const waitBound = 5 * time.Second

// gateRunner blocks every Scan until a token arrives on proceed (or ctx is
// cancelled) and records the peak number of concurrent scans.
type gateRunner struct {
	doc     *grype.Document
	proceed chan struct{}
	started chan struct{} // one send per Scan entry (buffered)
	cur     atomic.Int32
	max     atomic.Int32
	ctxErr  chan error // receives ctx.Err() when a scan is cancelled
	panics  atomic.Bool
	err     error
}

func newGate() *gateRunner {
	return &gateRunner{
		doc:     &grype.Document{},
		proceed: make(chan struct{}, 64),
		started: make(chan struct{}, 64),
		ctxErr:  make(chan error, 64),
	}
}

func (g *gateRunner) Scan(ctx context.Context, _ harbor.ScanRequest) (*grype.Document, error) {
	n := g.cur.Add(1)
	defer g.cur.Add(-1)
	for {
		m := g.max.Load()
		if n <= m || g.max.CompareAndSwap(m, n) {
			break
		}
	}
	g.started <- struct{}{}
	select {
	case <-g.proceed:
	case <-ctx.Done():
		g.ctxErr <- ctx.Err()
		return nil, ctx.Err()
	}
	if g.panics.Load() {
		panic("boom")
	}
	return g.doc, g.err
}

func (g *gateRunner) Version(context.Context) (string, time.Time, error) { return "", time.Time{}, nil }

func gateServer(n int, g *gateRunner) *Server {
	return New(Options{Scanner: harbor.Scanner{Name: "Grype"}, WorkerConcurrency: n}, job.NewMemoryStore(), g, newSBOM())
}

func recv(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(waitBound):
		t.Fatalf("timed out waiting for %s", what)
	}
}

func status(t *testing.T, s *Server, id string) job.Status {
	t.Helper()
	j, err := s.store.GetJob(job.VulnKey(id))
	if err != nil {
		t.Fatal(err)
	}
	return j.Status
}

func waitStatus(t *testing.T, s *Server, id string, want job.Status) *job.Job {
	t.Helper()
	deadline := time.Now().Add(waitBound)
	for time.Now().Before(deadline) {
		j, err := s.store.GetJob(job.VulnKey(id))
		if err != nil {
			t.Fatal(err)
		}
		if j.Status == want {
			return j
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("job %s never reached %s", id, want)
	return nil
}

func TestConcurrencyLimit(t *testing.T) {
	for _, n := range []int{1, 2} {
		g := newGate()
		s := gateServer(n, g)
		const total = 5
		ids := make([]string, total)
		for i := range ids {
			ids[i] = postScan(t, s)
		}
		for i := 0; i < n; i++ {
			recv(t, g.started, "initial scans")
		}
		running, pending := 0, 0
		for _, id := range ids {
			switch status(t, s, id) {
			case job.StatusRunning:
				running++
			case job.StatusPending:
				pending++
				if rr := do(s, http.MethodGet, BasePath+"/scan/"+id+"/report", nil, ""); rr.Code != http.StatusFound {
					t.Errorf("n=%d queued job report = %d, want 302", n, rr.Code)
				}
			}
		}
		if running != n || pending != total-n {
			t.Fatalf("n=%d running=%d pending=%d", n, running, pending)
		}
		// free slots one at a time; each frees exactly one queued job
		for i := 0; i < total; i++ {
			g.proceed <- struct{}{}
			if i < total-n {
				recv(t, g.started, "next queued scan")
			}
		}
		for _, id := range ids {
			if rr := waitFinished(t, s, id); rr.Code != http.StatusOK {
				t.Errorf("n=%d final report = %d", n, rr.Code)
			}
		}
		if m := g.max.Load(); int(m) != n {
			t.Errorf("n=%d peak concurrency = %d", n, m)
		}
		if err := s.Shutdown(context.Background()); err != nil {
			t.Errorf("Shutdown = %v", err)
		}
	}
}

func TestSlotReleasedAfterPanicAndError(t *testing.T) {
	g := newGate()
	s := gateServer(1, g)
	g.panics.Store(true)
	g.proceed <- struct{}{}
	id1 := postScan(t, s)
	waitStatus(t, s, id1, job.StatusFailed)
	g.panics.Store(false)
	g.err = errors.New("scan broke")
	g.proceed <- struct{}{}
	id2 := postScan(t, s)
	j := waitStatus(t, s, id2, job.StatusFailed)
	if j.Error == "" {
		t.Error("expected error message")
	}
	g.err = nil
	g.proceed <- struct{}{}
	id3 := postScan(t, s)
	waitStatus(t, s, id3, job.StatusFinished)
	// The slot is released after the final status write; Shutdown waits for
	// every job goroutine (wg.Done is the last defer), so the check is race-free.
	if err := s.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown = %v", err)
	}
	if len(s.sem) != 0 {
		t.Errorf("slots held: %d", len(s.sem))
	}
}

func TestShutdownCancelsInFlightScan(t *testing.T) {
	g := newGate()
	s := gateServer(1, g)
	s.grace = time.Second
	id := postScan(t, s)
	recv(t, g.started, "scan start")
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	begin := time.Now()
	err := s.Shutdown(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Shutdown = %v, want deadline exceeded", err)
	}
	if d := time.Since(begin); d > 3*time.Second {
		t.Fatalf("Shutdown took %v", d)
	}
	select {
	case e := <-g.ctxErr:
		if !errors.Is(e, context.Canceled) {
			t.Errorf("scan ctx err = %v", e)
		}
	default:
		t.Error("scan context was not cancelled")
	}
	j, _ := s.store.GetJob(job.VulnKey(id))
	if j.Status != job.StatusFailed || j.Error != "interrupted by shutdown" {
		t.Fatalf("job = %s %q", j.Status, j.Error)
	}
}

func TestShutdownWaitsForScanWithinBudget(t *testing.T) {
	g := newGate()
	s := gateServer(1, g)
	id := postScan(t, s)
	recv(t, g.started, "scan start")
	errCh := make(chan error, 1)
	ctx, cancel := context.WithTimeout(context.Background(), waitBound)
	defer cancel()
	go func() { errCh <- s.Shutdown(ctx) }()
	select {
	case err := <-errCh:
		t.Fatalf("Shutdown returned early: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	g.proceed <- struct{}{}
	if err := <-errCh; err != nil {
		t.Fatalf("Shutdown = %v", err)
	}
	if st := status(t, s, id); st != job.StatusFinished {
		t.Fatalf("status = %s", st)
	}
}

func TestShutdownFailsQueuedJobs(t *testing.T) {
	g := newGate()
	s := gateServer(1, g)
	s.grace = time.Second
	running := postScan(t, s)
	recv(t, g.started, "scan start")
	queued := []string{postScan(t, s), postScan(t, s)}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := s.Shutdown(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Shutdown = %v", err)
	}
	for _, id := range append(queued, running) {
		j, _ := s.store.GetJob(job.VulnKey(id))
		if j.Status != job.StatusFailed || j.Error != "interrupted by shutdown" {
			t.Errorf("job %s = %s %q", id, j.Status, j.Error)
		}
	}
	if n := len(g.started); n != 0 {
		t.Errorf("queued jobs must never start; %d extra starts", n)
	}
}

// A runner that ignores its context must not hang Shutdown; the job is
// still marked interrupted once the grace period lapses.
func TestShutdownGraceBoundsStuckScan(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	stuck := &stuckRunner{release: release, started: make(chan struct{}, 1)}
	s := New(Options{WorkerConcurrency: 1}, job.NewMemoryStore(), stuck, newSBOM())
	s.grace = 50 * time.Millisecond
	id := postScan(t, s)
	recv(t, stuck.started, "scan start")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	begin := time.Now()
	if err := s.Shutdown(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Shutdown = %v", err)
	}
	if d := time.Since(begin); d > 3*time.Second {
		t.Fatalf("Shutdown took %v", d)
	}
	if j, _ := s.store.GetJob(job.VulnKey(id)); j.Status != job.StatusFailed || j.Error != "interrupted by shutdown" {
		t.Fatalf("job = %s %q", j.Status, j.Error)
	}
}

type stuckRunner struct {
	release chan struct{}
	started chan struct{}
}

func (r *stuckRunner) Scan(context.Context, harbor.ScanRequest) (*grype.Document, error) {
	r.started <- struct{}{}
	<-r.release
	return &grype.Document{}, nil
}
func (r *stuckRunner) Version(context.Context) (string, time.Time, error) {
	return "", time.Time{}, nil
}

func TestScanAfterShutdownRejected(t *testing.T) {
	s := newServer(t, &fakeRunner{doc: &grype.Document{}})
	if err := s.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	rr := do(s, http.MethodPost, BasePath+"/scan", scanBody(), "")
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("POST after Shutdown = %d %s", rr.Code, rr.Body.String())
	}
	var e harbor.ErrorResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &e); err != nil || e.Error.Message == "" {
		t.Fatalf("bad error body %q: %v", rr.Body.String(), err)
	}
	if rr.Header().Get("Content-Type") != harbor.MimeTypeError {
		t.Errorf("content-type = %q", rr.Header().Get("Content-Type"))
	}
	// reads keep working while draining
	if rr := do(s, http.MethodGet, "/healthz", nil, ""); rr.Code != http.StatusOK {
		t.Errorf("healthz = %d", rr.Code)
	}
}

func TestConcurrentPostsRaceShutdown(t *testing.T) {
	s := newServer(t, &fakeRunner{doc: &grype.Document{}})
	var wg sync.WaitGroup
	start := make(chan struct{})
	var accepted, rejected atomic.Int32
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			switch rr := do(s, http.MethodPost, BasePath+"/scan", scanBody(), ""); rr.Code {
			case http.StatusAccepted:
				accepted.Add(1)
			case http.StatusServiceUnavailable:
				rejected.Add(1)
			default:
				t.Errorf("POST = %d %s", rr.Code, rr.Body.String())
			}
		}()
	}
	close(start)
	if err := s.Shutdown(context.Background()); err != nil {
		t.Errorf("Shutdown = %v", err)
	}
	wg.Wait()
	// Anything accepted before closing must have been drained or be settled
	// by a second Shutdown; nothing may remain non-terminal.
	if err := s.Shutdown(context.Background()); err != nil {
		t.Errorf("second Shutdown = %v", err)
	}
	if accepted.Load()+rejected.Load() != 32 {
		t.Errorf("accepted=%d rejected=%d", accepted.Load(), rejected.Load())
	}
	s.mu.Lock()
	left := len(s.active)
	s.mu.Unlock()
	if left != 0 {
		t.Errorf("%d jobs still active", left)
	}
}
