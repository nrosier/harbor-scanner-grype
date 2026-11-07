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

func TestCreateSetKinds(t *testing.T) {
	spdx := harbor.MediaTypeSPDX
	tests := []struct {
		name string
		keys []Key
		want int
	}{
		{"vuln only", []Key{{Kind: KindVulnerability}}, 1},
		{"vuln+sbom", []Key{{Kind: KindVulnerability}, {Kind: KindSBOM, SBOMMediaType: spdx}}, 2},
		{"sbom only", []Key{{Kind: KindSBOM, SBOMMediaType: spdx}}, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewMemoryStore()
			jobs, err := s.CreateSet(req("lib/app"), tt.keys)
			if err != nil || len(jobs) != tt.want {
				t.Fatalf("CreateSet: jobs=%d err=%v", len(jobs), err)
			}
			for i, j := range jobs {
				if j.ID != jobs[0].ID || j.ID == "" {
					t.Fatalf("all jobs must share one ID")
				}
				if j.Status != StatusPending || j.Kind != tt.keys[i].Kind || j.SBOMMediaType != tt.keys[i].SBOMMediaType {
					t.Fatalf("unexpected job %+v", j)
				}
				got, err := s.GetJob(j.Key())
				if err != nil || got.Key() != j.Key() {
					t.Fatalf("GetJob(%+v): %v %v", j.Key(), got, err)
				}
			}
		})
	}
}

func TestCreateSetRejectsBadKeys(t *testing.T) {
	spdx := harbor.MediaTypeSPDX
	for name, keys := range map[string][]Key{
		"empty":         nil,
		"sbom no media": {{Kind: KindSBOM}},
		"vuln w/ media": {{Kind: KindVulnerability, SBOMMediaType: spdx}},
		"unknown kind":  {{Kind: "x"}},
		"duplicate":     {{Kind: KindVulnerability}, {Kind: KindVulnerability}},
	} {
		if _, err := NewMemoryStore().CreateSet(req("a"), keys); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
}

func TestSetIndependentStatusAndErrors(t *testing.T) {
	s := NewMemoryStore()
	jobs, err := s.CreateSet(req("a"), []Key{{Kind: KindVulnerability}, {Kind: KindSBOM, SBOMMediaType: harbor.MediaTypeSPDX}})
	if err != nil {
		t.Fatal(err)
	}
	vk, sk := jobs[0].Key(), jobs[1].Key()

	if err := s.SetJobRunning(sk); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GetJob(vk); got.Status != StatusPending {
		t.Fatalf("vuln must stay Pending, got %s", got.Status)
	}
	if err := s.SetJobReport(vk, &harbor.ScanReport{Severity: harbor.SevLow}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetJobError(sk, "syft failed"); err != nil {
		t.Fatal(err)
	}
	v, _ := s.GetJob(vk)
	b, _ := s.GetJob(sk)
	if v.Status != StatusFinished || v.Report == nil || v.Error != "" || v.SBOMReport != nil {
		t.Fatalf("vuln job wrong: %+v", v)
	}
	if b.Status != StatusFailed || b.Error != "syft failed" || b.Report != nil || b.SBOMReport != nil {
		t.Fatalf("sbom job wrong: %+v", b)
	}

	// Reverse: vuln fails, sbom finishes.
	jobs, _ = s.CreateSet(req("a"), []Key{{Kind: KindVulnerability}, {Kind: KindSBOM, SBOMMediaType: harbor.MediaTypeSPDX}})
	vk, sk = jobs[0].Key(), jobs[1].Key()
	_ = s.SetJobError(vk, "grype failed")
	_ = s.SetJobSBOM(sk, &harbor.SBOMReport{MediaType: harbor.MediaTypeSPDX})
	v, _ = s.GetJob(vk)
	b, _ = s.GetJob(sk)
	if v.Status != StatusFailed || v.Error != "grype failed" {
		t.Fatalf("vuln job wrong: %+v", v)
	}
	if b.Status != StatusFinished || b.SBOMReport == nil || b.Error != "" {
		t.Fatalf("sbom job wrong: %+v", b)
	}
}

func TestSBOMMediaTypeIsolation(t *testing.T) {
	s := NewMemoryStore()
	jobs, _ := s.CreateSet(req("a"), []Key{{Kind: KindSBOM, SBOMMediaType: harbor.MediaTypeSPDX}})
	id := jobs[0].ID
	if _, err := s.GetJob(SBOMKey(id, "application/vnd.cyclonedx+json")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("other media type: want ErrNotFound, got %v", err)
	}
	if err := s.SetJobRunning(SBOMKey(id, "other")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("SetJobRunning other media type: got %v", err)
	}
	if _, err := s.GetJob(VulnKey(id)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("sbom-only set has no vuln job, got %v", err)
	}
	if _, err := s.Get(id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("legacy Get on sbom-only set: got %v", err)
	}
	if _, err := s.GetJob(SBOMKey(id, harbor.MediaTypeSPDX)); err != nil {
		t.Fatal(err)
	}
}

func TestGetJobUnknownAndCopy(t *testing.T) {
	s := NewMemoryStore()
	if _, err := s.GetJob(VulnKey("nope")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	for name, err := range map[string]error{
		"running": s.SetJobRunning(VulnKey("nope")),
		"report":  s.SetJobReport(VulnKey("nope"), nil),
		"sbom":    s.SetJobSBOM(SBOMKey("nope", harbor.MediaTypeSPDX), nil),
		"error":   s.SetJobError(VulnKey("nope"), "x"),
	} {
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("%s: want ErrNotFound, got %v", name, err)
		}
	}
	jobs, _ := s.CreateSet(req("a"), []Key{{Kind: KindVulnerability}})
	a, _ := s.GetJob(jobs[0].Key())
	a.Status = StatusFailed
	if b, _ := s.GetJob(jobs[0].Key()); b.Status != StatusPending {
		t.Fatalf("GetJob must return a copy")
	}
}

func TestCleanupRemovesWholeSet(t *testing.T) {
	now := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	s := NewMemoryStore()
	s.Clock = func() time.Time { return now }
	keys := []Key{{Kind: KindVulnerability}, {Kind: KindSBOM, SBOMMediaType: harbor.MediaTypeSPDX}}

	done, _ := s.CreateSet(req("done"), keys)
	_ = s.SetJobReport(done[0].Key(), &harbor.ScanReport{})
	_ = s.SetJobError(done[1].Key(), "x")
	partial, _ := s.CreateSet(req("partial"), keys)
	_ = s.SetJobReport(partial[0].Key(), &harbor.ScanReport{}) // sbom still Pending

	now = now.Add(2 * time.Hour)
	fresh, _ := s.CreateSet(req("fresh"), keys)
	_ = s.SetJobReport(fresh[0].Key(), &harbor.ScanReport{})
	_ = s.SetJobError(fresh[1].Key(), "x")

	if removed := s.Cleanup(time.Hour); removed != 2 {
		t.Fatalf("want 2 jobs (one set) removed, got %d", removed)
	}
	for _, j := range done {
		if _, err := s.GetJob(j.Key()); !errors.Is(err, ErrNotFound) {
			t.Fatalf("%+v should be gone", j.Key())
		}
	}
	for _, j := range append(partial, fresh...) {
		if _, err := s.GetJob(j.Key()); err != nil {
			t.Fatalf("%+v must survive: %v", j.Key(), err)
		}
	}

	// A late-finishing sibling keeps the whole set alive.
	_ = s.SetJobError(partial[1].Key(), "late")
	if removed := s.Cleanup(time.Hour); removed != 0 {
		t.Fatalf("recently updated set must survive, removed %d", removed)
	}
}

func TestTerminalStatesAreSticky(t *testing.T) {
	s := NewMemoryStore()
	// Pending -> Failed (queued job interrupted) still works.
	q, _ := s.Create(harbor.ScanRequest{})
	if err := s.SetError(q.ID, "interrupted by shutdown"); err != nil {
		t.Fatal(err)
	}
	// Late results must not flip Failed -> Finished.
	if err := s.SetReport(q.ID, &harbor.ScanReport{}); err != nil {
		t.Fatalf("late report should be a silent no-op, got %v", err)
	}
	if err := s.SetRunning(q.ID); err != nil {
		t.Fatal(err)
	}
	got, _ := s.Get(q.ID)
	if got.Status != StatusFailed || got.Error != "interrupted by shutdown" || got.Report != nil {
		t.Fatalf("failed job mutated: %+v", got)
	}

	// Finished is also terminal (SBOM and error cannot overwrite it).
	set, _ := s.CreateSet(harbor.ScanRequest{}, []Key{SBOMKey("", harbor.MediaTypeSPDX)})
	k := set[0].Key()
	_ = s.SetJobRunning(k)
	rep := &harbor.SBOMReport{MediaType: harbor.MediaTypeSPDX}
	if err := s.SetJobSBOM(k, rep); err != nil {
		t.Fatal(err)
	}
	_ = s.SetJobError(k, "late failure")
	_ = s.SetJobSBOM(k, &harbor.SBOMReport{})
	g, _ := s.GetJob(k)
	if g.Status != StatusFinished || g.SBOMReport != rep || g.Error != "" {
		t.Fatalf("finished job mutated: %+v", g)
	}
}
