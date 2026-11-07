package grype

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func newTestCache(clk *fakeClock, fetch func(context.Context) (time.Time, error)) *DBTimeCache {
	return NewDBTimeCache(DBTimeCacheOptions{
		Fetch: fetch, TTL: 5 * time.Minute, ErrBackoff: 30 * time.Second,
		Now: clk.Now, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
}

func TestDBTimeCacheTTL(t *testing.T) {
	clk := &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	var calls int
	val := time.Date(2026, 1, 1, 1, 0, 0, 0, time.UTC)
	c := newTestCache(clk, func(context.Context) (time.Time, error) { calls++; return val, nil })

	if got := c.Get(); !got.Equal(val) || calls != 1 {
		t.Fatalf("first: got %v calls %d", got, calls)
	}
	val = val.Add(time.Hour)
	clk.Advance(4 * time.Minute)
	if got := c.Get(); got.Equal(val) || calls != 1 {
		t.Fatalf("within TTL must be cached: got %v calls %d", got, calls)
	}
	clk.Advance(time.Minute)
	if got := c.Get(); !got.Equal(val) || calls != 2 {
		t.Fatalf("after TTL must refetch: got %v calls %d", got, calls)
	}
}

func TestDBTimeCacheErrorKeepsLastGood(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	good := time.Date(2026, 1, 1, 1, 0, 0, 0, time.UTC)
	var calls int
	var fail bool
	c := newTestCache(clk, func(context.Context) (time.Time, error) {
		calls++
		if fail {
			return time.Time{}, errors.New("boom")
		}
		return good, nil
	})
	c.Get()
	fail = true
	clk.Advance(5 * time.Minute)
	if got := c.Get(); !got.Equal(good) || calls != 2 {
		t.Fatalf("error must keep last good: got %v calls %d", got, calls)
	}
	// Within backoff: no retry.
	clk.Advance(10 * time.Second)
	c.Get()
	if calls != 2 {
		t.Fatalf("retry within backoff: calls %d", calls)
	}
	// After backoff: retry, and recovery picks up the new value.
	fail = false
	good = good.Add(time.Hour)
	clk.Advance(30 * time.Second)
	if got := c.Get(); !got.Equal(good) || calls != 3 {
		t.Fatalf("recovery: got %v calls %d", got, calls)
	}
}

func TestDBTimeCacheNeverGoodIsZero(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	var calls int
	c := newTestCache(clk, func(context.Context) (time.Time, error) { calls++; return time.Time{}, errors.New("boom") })
	if got := c.Get(); !got.IsZero() {
		t.Fatalf("want zero, got %v", got)
	}
	clk.Advance(30 * time.Second)
	if got := c.Get(); !got.IsZero() || calls != 2 {
		t.Fatalf("want zero and retry after backoff, got %v calls %d", got, calls)
	}
}

func TestDBTimeCacheZeroResultKeepsLastGood(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	good := time.Date(2026, 1, 1, 1, 0, 0, 0, time.UTC)
	first := true
	c := newTestCache(clk, func(context.Context) (time.Time, error) {
		if first {
			first = false
			return good, nil
		}
		return time.Time{}, nil
	})
	c.Get()
	clk.Advance(5 * time.Minute)
	if got := c.Get(); !got.Equal(good) {
		t.Fatalf("got %v", got)
	}
}

func TestDBTimeCachePrime(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	var calls int
	primed := time.Date(2026, 1, 1, 1, 0, 0, 0, time.UTC)
	c := newTestCache(clk, func(context.Context) (time.Time, error) { calls++; return primed.Add(time.Hour), nil })
	c.Prime(primed)
	if got := c.Get(); !got.Equal(primed) || calls != 0 {
		t.Fatalf("got %v calls %d", got, calls)
	}
	clk.Advance(5 * time.Minute)
	if got := c.Get(); got.Equal(primed) || calls != 1 {
		t.Fatalf("got %v calls %d", got, calls)
	}
}

func TestDBTimeCacheConcurrentSingleFetch(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	var calls atomic.Int32
	val := time.Date(2026, 1, 1, 1, 0, 0, 0, time.UTC)
	c := newTestCache(clk, func(context.Context) (time.Time, error) {
		calls.Add(1)
		time.Sleep(20 * time.Millisecond)
		return val, nil
	})
	var wg sync.WaitGroup
	for range 64 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if got := c.Get(); !got.Equal(val) {
				t.Errorf("got %v", got)
			}
		}()
	}
	wg.Wait()
	if n := calls.Load(); n != 1 {
		t.Fatalf("fetch calls = %d, want 1", n)
	}
}

func TestDBTimeCacheFetchHasDeadline(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	c := NewDBTimeCache(DBTimeCacheOptions{
		TTL: time.Minute, FetchTimeout: 2 * time.Second, Now: clk.Now,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Fetch: func(ctx context.Context) (time.Time, error) {
			dl, ok := ctx.Deadline()
			if !ok || time.Until(dl) > 2*time.Second {
				t.Errorf("fetch ctx deadline missing or too far: %v %v", dl, ok)
			}
			return time.Time{}, nil
		},
	})
	c.Get()
}
