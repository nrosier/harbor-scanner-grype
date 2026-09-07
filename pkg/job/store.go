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

// Job is one scan request and its outcome.
type Job struct {
	ID        string
	Status    Status
	Request   harbor.ScanRequest
	Report    *harbor.ScanReport // set when Status == StatusFinished
	Error     string             // set when Status == StatusFailed
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Store persists jobs. All methods must be safe for concurrent use.
type Store interface {
	// Create stores a new Pending job and returns its unique ID.
	Create(req harbor.ScanRequest) (*Job, error)
	// Get returns a copy of the job or ErrNotFound.
	Get(id string) (*Job, error)
	// SetRunning marks the job Running.
	SetRunning(id string) error
	// SetReport stores the report and marks the job Finished.
	SetReport(id string, report *harbor.ScanReport) error
	// SetError stores the message and marks the job Failed.
	SetError(id string, msg string) error
	// Cleanup removes Finished/Failed jobs whose UpdatedAt is older than
	// ttl and returns how many were removed. Pending/Running jobs are kept.
	Cleanup(ttl time.Duration) int
}

// MemoryStore is the in-memory Store. Clock is injectable for tests
// (defaults to time.Now).
type MemoryStore struct {
	Clock func() time.Time
	mu    sync.Mutex
	jobs  map[string]*Job
}

// NewMemoryStore returns an empty store using time.Now.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{Clock: time.Now, jobs: make(map[string]*Job)}
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
	id, err := newID()
	if err != nil {
		return nil, err
	}
	now := s.Clock()
	j := &Job{
		ID:        id,
		Status:    StatusPending,
		Request:   req,
		CreatedAt: now,
		UpdatedAt: now,
	}
	s.mu.Lock()
	s.jobs[id] = j
	s.mu.Unlock()
	return copyJob(j), nil
}

func (s *MemoryStore) Get(id string) (*Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	j, ok := s.jobs[id]
	if !ok {
		return nil, ErrNotFound
	}
	return copyJob(j), nil
}

func (s *MemoryStore) SetRunning(id string) error {
	return s.update(id, func(j *Job) { j.Status = StatusRunning })
}

func (s *MemoryStore) SetReport(id string, report *harbor.ScanReport) error {
	return s.update(id, func(j *Job) {
		j.Status = StatusFinished
		j.Report = report
	})
}

func (s *MemoryStore) SetError(id string, msg string) error {
	return s.update(id, func(j *Job) {
		j.Status = StatusFailed
		j.Error = msg
	})
}

// update applies fn to the stored job and refreshes UpdatedAt.
func (s *MemoryStore) update(id string, fn func(*Job)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	j, ok := s.jobs[id]
	if !ok {
		return ErrNotFound
	}
	fn(j)
	j.UpdatedAt = s.Clock()
	return nil
}

// Cleanup removes Finished/Failed jobs whose UpdatedAt is older than ttl.
// A non-positive ttl removes nothing (SCANNER_JOB_TTL=0 means never).
func (s *MemoryStore) Cleanup(ttl time.Duration) int {
	if ttl <= 0 {
		return 0
	}
	cutoff := s.Clock().Add(-ttl)
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := 0
	for id, j := range s.jobs {
		if (j.Status == StatusFinished || j.Status == StatusFailed) && j.UpdatedAt.Before(cutoff) {
			delete(s.jobs, id)
			removed++
		}
	}
	return removed
}
