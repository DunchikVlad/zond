package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/DunchikVlad/zond/internal/verdict"
	"github.com/pressly/goose/v3"
)

func openTest(t *testing.T) *Store {
	t.Helper()
	st, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func mustSaveScan(t *testing.T, st *Store, id string) {
	t.Helper()
	err := st.SaveScan(context.Background(), &Scan{
		ID: id, SourceName: "x", Profile: "quick", Status: "running", StartedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("SaveScan: %v", err)
	}
}

func mustSaveVerdicts(t *testing.T, st *Store, vs ...verdict.Verdict) {
	t.Helper()
	if err := st.SaveVerdicts(context.Background(), vs); err != nil {
		t.Fatalf("SaveVerdicts: %v", err)
	}
}

func testVerdict(id, scanID string) verdict.Verdict {
	return verdict.Verdict{
		ID:               id,
		ScanID:           scanID,
		Table:            "users",
		Path:             "email",
		NativeType:       "String",
		Label:            verdict.Label("EMAIL"),
		Sensitivity:      verdict.SensitivityPII,
		Confidence:       0.9,
		EvidenceLayer:    verdict.LayerEnsemble,
		Evidence:         map[string]any{"rules": map[string]any{"rules/email": map[string]any{"matched": 9, "total": 10}}},
		TaxonomyVersion:  "1.0.0",
		DetectorsVersion: "1",
		SampleSize:       10,
		ReviewStatus:     verdict.StatusAutoAccepted,
		CreatedAt:        time.Now().UTC(),
	}
}

func TestSaveAndListRoundTrip(t *testing.T) {
	st := openTest(t)
	ctx := context.Background()
	now := time.Now().UTC()
	if err := st.SaveScan(ctx, &Scan{ID: "s1", SourceName: "ch-test", Profile: "deep", Status: "running", StartedAt: now}); err != nil {
		t.Fatalf("SaveScan: %v", err)
	}
	v := testVerdict("v1", "s1")
	if err := st.SaveVerdicts(ctx, []verdict.Verdict{v}); err != nil {
		t.Fatalf("SaveVerdicts: %v", err)
	}
	got, err := st.ListVerdicts(ctx, "s1")
	if err != nil {
		t.Fatalf("ListVerdicts: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("ожидался 1 вердикт, получено %d", len(got))
	}
	g := got[0]
	if g.ID != "v1" || g.Label != "EMAIL" || g.Confidence != 0.9 || g.Sensitivity != verdict.SensitivityPII {
		t.Fatalf("round-trip исказил вердикт: %+v", g)
	}
	if g.Evidence["rules"] == nil {
		t.Fatalf("evidence потерялся: %+v", g.Evidence)
	}
}

func TestSaveVerdictsIdempotent(t *testing.T) {
	st := openTest(t)
	ctx := context.Background()
	mustSaveScan(t, st, "s1")
	v := testVerdict("v1", "s1")
	if err := st.SaveVerdicts(ctx, []verdict.Verdict{v}); err != nil {
		t.Fatalf("первая вставка: %v", err)
	}
	v.Confidence = 0.5
	v.ReviewStatus = verdict.StatusPending
	if err := st.SaveVerdicts(ctx, []verdict.Verdict{v}); err != nil {
		t.Fatalf("повторная вставка: %v", err)
	}
	got, _ := st.ListVerdicts(ctx, "s1")
	if len(got) != 1 || got[0].Confidence != 0.5 || got[0].ReviewStatus != verdict.StatusPending {
		t.Fatalf("идемпотентность не сработала: %+v", got)
	}
}

func TestMarkTableAndFailedTables(t *testing.T) {
	st := openTest(t)
	ctx := context.Background()
	mustSaveScan(t, st, "s1")
	if err := st.MarkTable(ctx, "s1", "users", 100, "done", ""); err != nil {
		t.Fatalf("MarkTable: %v", err)
	}
	if err := st.MarkTable(ctx, "s1", "events", 0, "failed", "нет прав"); err != nil {
		t.Fatalf("MarkTable failed: %v", err)
	}
	failed, err := st.FailedTables(ctx, "s1")
	if err != nil || len(failed) != 1 || failed[0] != "events: нет прав" {
		t.Fatalf("FailedTables: %v %v", failed, err)
	}
}

func TestFinishScanUpdates(t *testing.T) {
	st := openTest(t)
	ctx := context.Background()
	mustSaveScan(t, st, "s1")
	fin := time.Now().UTC()
	if err := st.FinishScan(ctx, "s1", "done", `{"columns_total":5}`, fin); err != nil {
		t.Fatalf("FinishScan: %v", err)
	}
	if err := st.FinishScan(ctx, "ghost", "done", "{}", fin); err == nil {
		t.Fatal("FinishScan несуществующего прогона должен падать")
	}
}

func TestVerdictSummary(t *testing.T) {
	st := openTest(t)
	ctx := context.Background()
	mustSaveScan(t, st, "s1")
	mk := func(id, label string, layer verdict.EvidenceLayer, status verdict.ReviewStatus) verdict.Verdict {
		v := testVerdict(id, "s1")
		v.Label = verdict.Label(label)
		v.EvidenceLayer = layer
		v.ReviewStatus = status
		v.Path = id
		return v
	}
	mustSaveVerdicts(t, st,
		mk("a", "EMAIL", verdict.LayerRules, verdict.StatusAutoAccepted),
		mk("b", "EMAIL", verdict.LayerRules, verdict.StatusPending),
		mk("c", "TAX_ID", verdict.LayerRules, verdict.StatusAutoAccepted),
	)
	sum, err := st.VerdictSummary(ctx, "s1")
	if err != nil {
		t.Fatalf("VerdictSummary: %v", err)
	}
	if sum.Total != 3 || sum.ByLabel["EMAIL"] != 2 || sum.ByStatus["pending"] != 1 || sum.ByLayer["rules"] != 3 {
		t.Fatalf("неверные агрегаты: %+v", sum)
	}
}

func TestMigrationsUpDownUp(t *testing.T) {
	// blueprint п. 16.9: up → down → up на чистой БД + smoke query (п. 18.1)
	path := filepath.Join(t.TempDir(), "mig.db")

	st, err := Open(path)
	if err != nil {
		t.Fatalf("open#1: %v", err)
	}
	st.Close()

	db, err := openRaw(path)
	if err != nil {
		t.Fatalf("raw open: %v", err)
	}
	var n int
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'verdicts'`).Scan(&n); err != nil || n != 1 {
		db.Close()
		t.Fatalf("smoke query после up: n=%d err=%v", n, err)
	}
	if err := gooseDownAll(db); err != nil {
		db.Close()
		t.Fatalf("down: %v", err)
	}
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'verdicts'`).Scan(&n); err != nil || n != 0 {
		db.Close()
		t.Fatalf("smoke query после down: n=%d err=%v", n, err)
	}
	db.Close()

	st2, err := Open(path)
	if err != nil {
		t.Fatalf("open#2 после down: %v", err)
	}
	st2.Close()
}

// openRaw открывает БД без миграций.
func openRaw(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

// gooseDownAll откатывает все миграции.
func gooseDownAll(db *sql.DB) error {
	if err := goose.SetDialect("sqlite3"); err != nil {
		return err
	}
	return goose.DownTo(db, "migrations", 0)
}
