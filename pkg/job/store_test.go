package job

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/TechPrototyper/harbor-scanner-grype/pkg/harbor"
)

func mustCreate(t *testing.T, s Store, r harbor.ScanRequest) *Job {
	t.Helper()
	j, err := s.Create(r)
	if err != nil || j == nil {
		t.Fatalf("Create failed: job=%v err=%v", j, err)
	}
	return j
}

func mustGet(t *testing.T, s Store, id string) *Job {
	t.Helper()
	j, err := s.Get(id)
	if err != nil || j == nil {
		t.Fatalf("Get(%s) failed: job=%v err=%v", id, j, err)
	}
	return j
}

func req(repo string) harbor.ScanRequest {
	return harbor.ScanRequest{
		Registry: harbor.Registry{URL: "https://harbor.example", Authorization: "Basic abc"},
		Artifact: harbor.Artifact{Repository: repo, Digest: "sha256:0000", MimeType: harbor.MimeTypeOCIArtifact},
	}
}

func TestCreateReturnsUniquePendingJobs(t *testing.T) {
	s := NewMemoryStore()
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		j, err := s.Create(req("lib/app"))
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if j.ID == "" || seen[j.ID] {
			t.Fatalf("ID must be unique and non-empty, got %q", j.ID)
		}
		seen[j.ID] = true
		if j.Status != StatusPending {
			t.Fatalf("new job must be Pending, got %s", j.Status)
		}
		if j.Request.Artifact.Repository != "lib/app" {
			t.Fatalf("request not stored")
		}
		if j.CreatedAt.IsZero() || j.UpdatedAt.IsZero() {
			t.Fatalf("timestamps must be set")
		}
	}
}

func TestGetUnknownIsErrNotFound(t *testing.T) {
	s := NewMemoryStore()
	if _, err := s.Get("nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	if err := s.SetRunning("nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("SetRunning unknown: want ErrNotFound, got %v", err)
	}
	if err := s.SetReport("nope", &harbor.ScanReport{}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("SetReport unknown: want ErrNotFound, got %v", err)
	}
	if err := s.SetError("nope", "x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("SetError unknown: want ErrNotFound, got %v", err)
	}
}

func TestLifecycleToFinished(t *testing.T) {
	s := NewMemoryStore()
	j := mustCreate(t, s, req("lib/app"))
	if err := s.SetRunning(j.ID); err != nil {
		t.Fatal(err)
	}
	got := mustGet(t, s, j.ID)
	if got.Status != StatusRunning {
		t.Fatalf("want Running, got %s", got.Status)
	}
	rep := &harbor.ScanReport{Severity: harbor.SevHigh}
	if err := s.SetReport(j.ID, rep); err != nil {
		t.Fatal(err)
	}
	got = mustGet(t, s, j.ID)
	if got.Status != StatusFinished || got.Report == nil || got.Report.Severity != harbor.SevHigh {
		t.Fatalf("want Finished with report, got %+v", got)
	}
	if got.Error != "" {
		t.Fatalf("finished job must have no error")
	}
}

func TestLifecycleToFailed(t *testing.T) {
	s := NewMemoryStore()
	j := mustCreate(t, s, req("lib/app"))
	if err := s.SetError(j.ID, "grype exploded"); err != nil {
		t.Fatal(err)
	}
	got := mustGet(t, s, j.ID)
	if got.Status != StatusFailed || got.Error != "grype exploded" || got.Report != nil {
		t.Fatalf("want Failed with message, got %+v", got)
	}
}

func TestGetReturnsCopy(t *testing.T) {
	s := NewMemoryStore()
	j := mustCreate(t, s, req("lib/app"))
	a := mustGet(t, s, j.ID)
	a.Status = StatusFailed
	a.Request.Artifact.Repository = "tampered"
	b := mustGet(t, s, j.ID)
	if b.Status != StatusPending || b.Request.Artifact.Repository != "lib/app" {
		t.Fatalf("Get must return a copy, mutation leaked: %+v", b)
	}
}

func TestCleanupRemovesOnlyOldTerminalJobs(t *testing.T) {
	now := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	s := NewMemoryStore()
	s.Clock = func() time.Time { return now }

	oldDone := mustCreate(t, s, req("a"))
	_ = s.SetReport(oldDone.ID, &harbor.ScanReport{})
	oldFailed := mustCreate(t, s, req("b"))
	_ = s.SetError(oldFailed.ID, "x")
	oldPending := mustCreate(t, s, req("c"))
	oldRunning := mustCreate(t, s, req("d"))
	_ = s.SetRunning(oldRunning.ID)

	now = now.Add(2 * time.Hour)
	freshDone := mustCreate(t, s, req("e"))
	_ = s.SetReport(freshDone.ID, &harbor.ScanReport{})

	removed := s.Cleanup(time.Hour)
	if removed != 2 {
		t.Fatalf("want 2 removed (old finished + old failed), got %d", removed)
	}
	for _, id := range []string{oldDone.ID, oldFailed.ID} {
		if _, err := s.Get(id); !errors.Is(err, ErrNotFound) {
			t.Fatalf("job %s should be gone", id)
		}
	}
	for _, id := range []string{oldPending.ID, oldRunning.ID, freshDone.ID} {
		if _, err := s.Get(id); err != nil {
			t.Fatalf("job %s must survive cleanup: %v", id, err)
		}
	}
}

func TestConcurrentAccessIsSafe(t *testing.T) {
	s := NewMemoryStore()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			j, err := s.Create(req("lib/app"))
			if err != nil {
				t.Error(err)
				return
			}
			_ = s.SetRunning(j.ID)
			_ = s.SetReport(j.ID, &harbor.ScanReport{})
			if _, err := s.Get(j.ID); err != nil {
				t.Error(err)
			}
			s.Cleanup(time.Hour)
		}()
	}
	wg.Wait()
}
