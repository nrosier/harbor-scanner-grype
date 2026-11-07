package grype

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// DBTimeCache serves the vulnerability database build time with a TTL, so
// /metadata stays current when grype auto-updates its DB without forking
// grype on every request.
//
// Get holds the mutex while fetching, so concurrent callers share a single
// fetch (single-flight); each fetch runs under a bounded context so a hung
// grype cannot block callers for longer than the fetch timeout.
//
// A failed (or zero-valued) refresh keeps serving the last good value and is
// retried after ErrBackoff rather than on every call. Only the first failure
// of a streak is logged at warn; later ones are logged at debug.
type DBTimeCache struct {
	fetch      func(ctx context.Context) (time.Time, error)
	ttl        time.Duration
	errBackoff time.Duration
	timeout    time.Duration
	now        func() time.Time
	logger     *slog.Logger

	mu        sync.Mutex
	value     time.Time // last good value; zero if none yet
	nextFetch time.Time // no fetch before this instant; zero means fetch now
	failing   bool
}

// DBTimeCacheOptions configures NewDBTimeCache. Zero fields get defaults:
// ErrBackoff min(TTL, 30s), FetchTimeout 10s, Now time.Now, Logger slog.Default().
type DBTimeCacheOptions struct {
	Fetch        func(ctx context.Context) (time.Time, error)
	TTL          time.Duration
	ErrBackoff   time.Duration
	FetchTimeout time.Duration
	Now          func() time.Time
	Logger       *slog.Logger
}

// NewDBTimeCache builds a cache; the first Get fetches (unless Prime was used).
func NewDBTimeCache(o DBTimeCacheOptions) *DBTimeCache {
	c := &DBTimeCache{fetch: o.Fetch, ttl: o.TTL, errBackoff: o.ErrBackoff, timeout: o.FetchTimeout, now: o.Now, logger: o.Logger}
	if c.errBackoff <= 0 {
		c.errBackoff = min(c.ttl, 30*time.Second)
	}
	if c.timeout <= 0 {
		c.timeout = 10 * time.Second
	}
	if c.now == nil {
		c.now = time.Now
	}
	if c.logger == nil {
		c.logger = slog.Default()
	}
	return c
}

// Prime seeds the cache with a value obtained elsewhere (e.g. at startup), so
// the first Get within the TTL does not fork grype again. A zero t is ignored.
func (c *DBTimeCache) Prime(t time.Time) {
	if t.IsZero() {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.value = t
	c.nextFetch = c.now().Add(c.ttl)
}

// Get returns the current DB build time, or the zero time if never known.
func (c *DBTimeCache) Get() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if !c.nextFetch.IsZero() && now.Before(c.nextFetch) {
		return c.value
	}
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()
	t, err := c.fetch(ctx)
	switch {
	case err != nil:
		c.nextFetch = now.Add(c.errBackoff)
		if c.failing {
			c.logger.Debug("vulnerability DB timestamp refresh failed", "error", err.Error())
		} else {
			c.logger.Warn("vulnerability DB timestamp refresh failed; serving last known value", "error", err.Error())
		}
		c.failing = true
	case t.IsZero():
		// grype reported no parseable build time: treat as unknown, keep last good.
		c.nextFetch = now.Add(c.errBackoff)
	default:
		c.value = t
		c.nextFetch = now.Add(c.ttl)
		c.failing = false
	}
	return c.value
}
