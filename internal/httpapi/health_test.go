package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fikua/fikua-lab-issuer/internal/registryclient"
)

// lister succeeds on its first call and fails afterwards, so the cache turns
// stale on its first background refresh.
type lister struct{ calls atomic.Int32 }

func (l *lister) ListSchemes(context.Context) ([]registryclient.Definition, error) {
	if l.calls.Add(1) == 1 {
		return nil, nil
	}
	return nil, errors.New("registry down")
}

func TestHealthPassThenWarnWhenTheCacheIsStale(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cache := registryclient.NewCache(&lister{})
	if err := cache.Start(ctx, 10*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	h := &Handler{cache: cache}
	get := func() (int, string) {
		rec := httptest.NewRecorder()
		h.health(rec, httptest.NewRequest(http.MethodGet, "/health", nil))
		return rec.Code, rec.Body.String()
	}
	if code, body := get(); code != 200 || body != `{"status":"pass","checks":{"cache:fresh":[{"status":"pass"}]}}`+"\n" {
		t.Fatalf("fresh cache: %d %s", code, body)
	}
	deadline := time.Now().Add(2 * time.Second)
	for !cache.Stale() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if code, body := get(); code != 200 || body != `{"status":"warn","checks":{"cache:fresh":[{"status":"warn"}]}}`+"\n" {
		t.Fatalf("stale cache: %d %s", code, body)
	}
}
