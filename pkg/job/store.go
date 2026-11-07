// Package job holds the state of asynchronous scan jobs between
// POST /scan and GET /scan/{id}/report. The default implementation is
// in-memory (single replica); the Store interface leaves room for Redis.
package job

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/TechPrototyper/harbor-scanner-grype/pkg/harbor"
)

// Status of a scan job.
type Status string

const (
	StatusPending  Status = "Pending"
	StatusRunning  Status = "Running"
	StatusFinished Status = "Finished"
	StatusFailed   Status = "Failed"
)

// ErrNotFound is returned by Get for unknown or expired job IDs.
var ErrNotFound = errors.New("job not found")

// Kind is the type of result a job produces.
type Kind string

const (
	KindVulnerability Kind = "vulnerability"
	KindSBOM          Kind = "sbom"
)

// Key identifies one job inside a scan set. All jobs of a scan share ID.
// SBOMMediaType is only set for KindSBOM. Both vulnerability MIME types
// share the single KindVulnerability job.
type Key struct {
	ID            string
	Kind          Kind
	SBOMMediaType string
}

// VulnKey returns the key of the vulnerability job of scan id.
func VulnKey(id string) Key { return Key{ID: id, Kind: KindVulnerability} }

// SBOMKey returns the key of the SBOM job of scan id for mediaType.
func SBOMKey(id, mediaType string) Key {
	return Key{ID: id, Kind: KindSBOM, SBOMMediaType: mediaType}
}

// Job is one scan request and its outcome.
type Job struct {
	ID            string
	Kind          Kind
	SBOMMediaType string // only for KindSBOM
	Status        Status
	Request       harbor.ScanRequest
	Report        *harbor.ScanReport // KindVulnerability, set when Status == StatusFinished
	SBOMReport    *harbor.SBOMReport // KindSBOM, set when Status == StatusFinished
	Error         string             // set when Status == StatusFailed
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// Key returns the job's key.
func (j *Job) Key() Key { return Key{ID: j.ID, Kind: j.Kind, SBOMMediaType: j.SBOMMediaType} }

// Store persists jobs. All methods must be safe for concurrent use.
//
// Create/Get/SetRunning/SetReport/SetError operate on the vulnerability job
// of a scan ID. CreateSet and the *Job methods address any job by Key.
type Store interface {
	// Create stores a new Pending vulnerability job and returns its unique ID.
	Create(req harbor.ScanRequest) (*Job, error)
	// Get returns a copy of the vulnerability job or ErrNotFound.
	Get(id string) (*Job, error)
	// SetRunning marks the vulnerability job Running.
	SetRunning(id string) error
	// SetReport stores the report and marks the vulnerability job Finished.
	SetReport(id string, report *harbor.ScanReport) error
	// SetError stores the message and marks the vulnerability job Failed.
	SetError(id string, msg string) error

	// CreateSet stores one Pending job per key under a single new scan ID
	// and returns copies in the order of keys. The ID of each given key is
	// ignored. Keys must be non-empty, unique, and SBOM keys need a media type.
	CreateSet(req harbor.ScanRequest, keys []Key) ([]*Job, error)
	// GetJob returns a copy of the job or ErrNotFound.
	GetJob(k Key) (*Job, error)
	// SetJobRunning marks the job Running.
	SetJobRunning(k Key) error
	// SetJobReport stores a vulnerability report and marks the job Finished.
	SetJobReport(k Key, report *harbor.ScanReport) error
	// SetJobSBOM stores an SBOM report and marks the job Finished.
	SetJobSBOM(k Key, report *harbor.SBOMReport) error
	// SetJobError stores the message and marks the job Failed.
	SetJobError(k Key, msg string) error

	// Cleanup removes scan sets whose jobs are all Finished/Failed and whose
	// latest UpdatedAt is older than ttl, and returns how many jobs were
	// removed. Sets with a Pending/Running job are kept whole.
	Cleanup(ttl time.Duration) int
}

// MemoryStore is the in-memory Store. Clock is injectable for tests
// (defaults to time.Now).
type MemoryStore struct {
	Clock func() time.Time
	mu    sync.Mutex
	sets  map[string]map[Key]*Job
}

// NewMemoryStore returns an empty store using time.Now.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{Clock: time.Now, sets: make(map[string]map[Key]*Job)}
}

// newID returns a random 32-character hex string.
func newID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate job id: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// copyJob returns a shallow copy so callers cannot mutate the stored job.
func copyJob(j *Job) *Job {
	c := *j
	return &c
}

func (s *MemoryStore) Create(req harbor.ScanRequest) (*Job, error) {
	jobs, err := s.CreateSet(req, []Key{{Kind: KindVulnerability}})
	if err != nil {
		return nil, err
	}
	return jobs[0], nil
}

func (s *MemoryStore) CreateSet(req harbor.ScanRequest, keys []Key) ([]*Job, error) {
	if len(keys) == 0 {
		return nil, errors.New("create job set: no keys")
	}
	set := make(map[Key]*Job, len(keys))
	id, err := newID()
	if err != nil {
		return nil, err
	}
	now := s.Clock()
	out := make([]*Job, 0, len(keys))
	for _, k := range keys {
		switch {
		case k.Kind == KindVulnerability && k.SBOMMediaType == "":
		case k.Kind == KindSBOM && k.SBOMMediaType != "":
		default:
			return nil, fmt.Errorf("create job set: invalid key %+v", k)
		}
		k.ID = id
		if _, dup := set[k]; dup {
			return nil, fmt.Errorf("create job set: duplicate key %+v", k)
		}
		j := &Job{
			ID:            id,
			Kind:          k.Kind,
			SBOMMediaType: k.SBOMMediaType,
			Status:        StatusPending,
			Request:       req,
			CreatedAt:     now,
			UpdatedAt:     now,
		}
		set[k] = j
		out = append(out, copyJob(j))
	}
	s.mu.Lock()
	s.sets[id] = set
	s.mu.Unlock()
	return out, nil
}

func (s *MemoryStore) Get(id string) (*Job, error) { return s.GetJob(VulnKey(id)) }

func (s *MemoryStore) GetJob(k Key) (*Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	j, ok := s.sets[k.ID][k]
	if !ok {
		return nil, ErrNotFound
	}
	return copyJob(j), nil
}

func (s *MemoryStore) SetRunning(id string) error { return s.SetJobRunning(VulnKey(id)) }

func (s *MemoryStore) SetReport(id string, report *harbor.ScanReport) error {
	return s.SetJobReport(VulnKey(id), report)
}

func (s *MemoryStore) SetError(id string, msg string) error { return s.SetJobError(VulnKey(id), msg) }

func (s *MemoryStore) SetJobRunning(k Key) error {
	return s.update(k, func(j *Job) { j.Status = StatusRunning })
}

func (s *MemoryStore) SetJobReport(k Key, report *harbor.ScanReport) error {
	return s.update(k, func(j *Job) {
		j.Status = StatusFinished
		j.Report = report
	})
}

func (s *MemoryStore) SetJobSBOM(k Key, report *harbor.SBOMReport) error {
	return s.update(k, func(j *Job) {
		j.Status = StatusFinished
		j.SBOMReport = report
	})
}

func (s *MemoryStore) SetJobError(k Key, msg string) error {
	return s.update(k, func(j *Job) {
		j.Status = StatusFailed
		j.Error = msg
	})
}

// update applies fn to the stored job and refreshes UpdatedAt. Finished and
// Failed are terminal: a later transition (e.g. a late report from a runner
// that ignored cancellation) is ignored and reported as success-no-op, so the
// first terminal outcome wins. Unknown jobs still return ErrNotFound.
func (s *MemoryStore) update(k Key, fn func(*Job)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	j, ok := s.sets[k.ID][k]
	if !ok {
		return ErrNotFound
	}
	if j.Status == StatusFinished || j.Status == StatusFailed {
		return nil
	}
	fn(j)
	j.UpdatedAt = s.Clock()
	return nil
}

// Cleanup removes whole scan sets whose jobs are all Finished/Failed and
// whose latest UpdatedAt is older than ttl. A non-positive ttl removes
// nothing (SCANNER_JOB_TTL=0 means never).
func (s *MemoryStore) Cleanup(ttl time.Duration) int {
	if ttl <= 0 {
		return 0
	}
	cutoff := s.Clock().Add(-ttl)
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := 0
	for id, set := range s.sets {
		expired := true
		for _, j := range set {
			if (j.Status != StatusFinished && j.Status != StatusFailed) || !j.UpdatedAt.Before(cutoff) {
				expired = false
				break
			}
		}
		if expired {
			removed += len(set)
			delete(s.sets, id)
		}
	}
	return removed
}
