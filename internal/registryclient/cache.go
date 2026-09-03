package registryclient

import (
	"context"
	"log"
	"sync"
	"time"
)

// Lister is the subset of Client this Cache depends on — satisfied by
// *Client, and by a fake in tests.
type Lister interface {
	ListSchemes(ctx context.Context) ([]Definition, error)
}

// Cache holds the last-known-good set of attestation definitions, refreshed
// periodically in the background. Callers always read from memory — a
// request being served by the issuer never blocks on a live registry call.
//
// The initial Start call is the only point that can fail: if the registry
// is unreachable at boot, the issuer has nothing to serve and should fail
// loudly rather than start with an empty catalogue. Every refresh after
// that is best-effort — a transient outage logs a warning and keeps
// serving the previous snapshot.
type Cache struct {
	lister Lister

	mu    sync.RWMutex
	defs  []Definition
	byID  map[string]Definition
	stale bool // true once at least one background refresh has failed
}

// NewCache builds a Cache around lister. Call Start before using it.
func NewCache(lister Lister) *Cache {
	return &Cache{lister: lister}
}

// Start performs the initial blocking fetch and then spawns a background
// goroutine that refreshes every interval. Returns an error if the initial
// fetch fails — callers should treat that as a fatal startup error.
func (c *Cache) Start(ctx context.Context, interval time.Duration) error {
	if err := c.refresh(ctx); err != nil {
		return err
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := c.refresh(ctx); err != nil {
					c.mu.Lock()
					c.stale = true
					c.mu.Unlock()
					log.Printf("registryclient: background refresh failed, serving last-known-good catalogue: %v", err)
				}
			}
		}
	}()
	return nil
}

func (c *Cache) refresh(ctx context.Context) error {
	defs, err := c.lister.ListSchemes(ctx)
	if err != nil {
		return err
	}
	byID := make(map[string]Definition, len(defs))
	for _, d := range defs {
		byID[d.Scheme.ID] = d
	}
	c.mu.Lock()
	c.defs = defs
	c.byID = byID
	c.stale = false
	c.mu.Unlock()
	return nil
}

// Stale reports whether the last background refresh attempt failed —
// callers are still served the previous known-good snapshot, but this
// signals degraded (not down) health.
func (c *Cache) Stale() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.stale
}

// All returns every cached attestation definition.
func (c *Cache) All() []Definition {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]Definition, len(c.defs))
	copy(out, c.defs)
	return out
}

// Get returns the cached definition for id, or false if not found.
func (c *Cache) Get(id string) (Definition, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	d, ok := c.byID[id]
	return d, ok
}
