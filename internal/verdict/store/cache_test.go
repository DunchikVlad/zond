package store

import (
	"context"
	"testing"
	"time"
)

func mustCachePut(t *testing.T, st *Store, key string, cv CachedVerdict) {
	t.Helper()
	if err := st.CachePut(context.Background(), key, cv); err != nil {
		t.Fatalf("CachePut: %v", err)
	}
}

func TestCachePutGetRoundTrip(t *testing.T) {
	st := openTest(t)
	ctx := context.Background()
	now := time.Now().UTC()
	cv := CachedVerdict{
		AgentID:     "zond-main",
		VerdictJSON: `{"label":"PHONE","confidence":0.9,"prompt_version":"1"}`,
		CreatedAt:   now,
		ExpiresAt:   now.Add(CacheTTLDefault),
	}
	if err := st.CachePut(ctx, "key-1", cv); err != nil {
		t.Fatalf("CachePut: %v", err)
	}
	got, ok, err := st.CacheGet(ctx, "key-1", now.Add(time.Minute))
	if err != nil || !ok {
		t.Fatalf("CacheGet: ok=%v err=%v", ok, err)
	}
	if got.AgentID != "zond-main" || got.VerdictJSON == "" {
		t.Fatalf("round-trip искажён: %+v", got)
	}
}

func TestCacheGetExpiredMiss(t *testing.T) {
	st := openTest(t)
	ctx := context.Background()
	now := time.Now().UTC()
	cv := CachedVerdict{AgentID: "a", VerdictJSON: "{}", CreatedAt: now.Add(-48 * time.Hour), ExpiresAt: now.Add(-24 * time.Hour)}
	if err := st.CachePut(ctx, "expired", cv); err != nil {
		t.Fatalf("CachePut: %v", err)
	}
	if _, ok, _ := st.CacheGet(ctx, "expired", now); ok {
		t.Fatal("просроченная запись вернулась")
	}
}

func TestCachePurgeExpired(t *testing.T) {
	st := openTest(t)
	ctx := context.Background()
	now := time.Now().UTC()
	mustCachePut(t, st, "old", CachedVerdict{AgentID: "a", VerdictJSON: "{}", CreatedAt: now.Add(-48 * time.Hour), ExpiresAt: now.Add(-time.Hour)})
	mustCachePut(t, st, "fresh", CachedVerdict{AgentID: "a", VerdictJSON: "{}", CreatedAt: now, ExpiresAt: now.Add(CacheTTLDefault)})
	n, err := st.CachePurgeExpired(ctx, now)
	if err != nil || n != 1 {
		t.Fatalf("Purge: n=%d err=%v, ожидалось 1", n, err)
	}
	if _, ok, _ := st.CacheGet(ctx, "fresh", now); !ok {
		t.Fatal("свежая запись удалена")
	}
}
