// Тесты дрейфа (blueprint п. 11.2 GET /api/v1/drift): новые/исчезнувшие
// колонки, смены лейблов (с учётом ручного relabel) и уверенности, порог
// шума confidence, выбор пары прогонов источника.
package drift

import (
	"context"
	"testing"
	"time"

	"github.com/DunchikVlad/zond/internal/verdict"
	"github.com/DunchikVlad/zond/internal/verdict/store"
)

func v(scanID, table, path, label string, conf float64) verdict.Verdict {
	return verdict.Verdict{
		ID: scanID + "/" + table + "/" + path, ScanID: scanID,
		Table: table, Path: path, NativeType: "String",
		Label: verdict.Label(label), Sensitivity: verdict.SensitivityPII,
		Confidence: conf, EvidenceLayer: verdict.LayerEnsemble,
		ReviewStatus: verdict.StatusAutoAccepted, CreatedAt: time.Now().UTC(),
	}
}

func TestCompareAddedRemovedChanged(t *testing.T) {
	base := []verdict.Verdict{
		v("s1", "users", "email", "EMAIL", 0.9),
		v("s1", "users", "phone", "PHONE", 0.8),
		v("s1", "orders", "note", "FREE_TEXT", 0.6),
	}
	curr := []verdict.Verdict{
		v("s2", "users", "email", "EMAIL", 0.92),       // без изменений (Δconf < 0.05)
		v("s2", "users", "phone", "MOBILE", 0.85),      // смена лейбла
		v("s2", "users", "passport", "PASSPORT", 0.99), // новая колонка
	}
	rep := Compare("s1", base, "s2", curr)
	if len(rep.Added) != 1 || rep.Added[0].Path != "passport" {
		t.Fatalf("added: %+v", rep.Added)
	}
	if len(rep.Removed) != 1 || rep.Removed[0].Path != "note" {
		t.Fatalf("removed: %+v", rep.Removed)
	}
	if len(rep.Changed) != 1 || rep.Changed[0].FromLabel != "PHONE" || rep.Changed[0].ToLabel != "MOBILE" {
		t.Fatalf("changed: %+v", rep.Changed)
	}
}

func TestCompareConfidenceNoise(t *testing.T) {
	base := []verdict.Verdict{v("s1", "t", "c", "EMAIL", 0.90)}
	curr := []verdict.Verdict{v("s2", "t", "c", "EMAIL", 0.96)} // Δ=0.06 ≥ порога
	rep := Compare("s1", base, "s2", curr)
	if len(rep.Changed) != 1 {
		t.Fatalf("смена ≥0.05 должна считаться дрейфом: %+v", rep.Changed)
	}
	curr[0].Confidence = 0.94 // Δ=0.04 < порога
	rep = Compare("s1", base, "s2", curr)
	if len(rep.Changed) != 0 {
		t.Fatalf("смена <0.05 — шум: %+v", rep.Changed)
	}
}

// Ручной relabel (final_label) — «текущее решение» в дрейфе (п. 5.4):
// дрейф считается по эффективному лейблу, а не по автоматическому.
func TestCompareUsesFinalLabel(t *testing.T) {
	base := []verdict.Verdict{v("s1", "t", "c", "EMAIL", 0.9)}
	curr := []verdict.Verdict{v("s2", "t", "c", "EMAIL", 0.9)}
	curr[0].FinalLabel = "PERSON_NAME" // ревьюер пере-классифицировал
	rep := Compare("s1", base, "s2", curr)
	if len(rep.Changed) != 1 || rep.Changed[0].ToLabel != "PERSON_NAME" {
		t.Fatalf("final_label: %+v", rep.Changed)
	}
}

func openStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

// BetweenLatest: текущий — свежайший не-running прогон источника, базовый —
// предыдущий; running-прогоны игнорируются; источник фильтруется.
func TestBetweenLatestPicksPair(t *testing.T) {
	st := openStore(t)
	ctx := context.Background()
	base := time.Now().UTC().Add(-3 * time.Hour)
	mk := func(id, source, status string, startedAt time.Time, vs []verdict.Verdict) {
		t.Helper()
		if err := st.SaveScan(ctx, &store.Scan{ID: id, SourceName: source, Profile: "quick",
			Status: status, StartedAt: startedAt}); err != nil {
			t.Fatalf("SaveScan: %v", err)
		}
		if err := st.SaveVerdicts(ctx, vs); err != nil {
			t.Fatalf("SaveVerdicts: %v", err)
		}
	}
	mk("s1", "ch", "done", base, []verdict.Verdict{v("s1", "t", "a", "EMAIL", 0.9)})
	mk("s2", "ch", "done", base.Add(time.Hour), []verdict.Verdict{
		v("s2", "t", "a", "EMAIL", 0.9), v("s2", "t", "b", "PHONE", 0.8)})
	mk("s3", "ch", "running", base.Add(2*time.Hour), nil) // игнорируется
	mk("x1", "mongo", "done", base.Add(3*time.Hour), nil) // другой источник

	rep, ok, err := BetweenLatest(ctx, st, "ch", nil)
	if err != nil || !ok {
		t.Fatalf("BetweenLatest: ok=%v err=%v", ok, err)
	}
	if rep.BaseScanID != "s1" || rep.CurrScanID != "s2" {
		t.Fatalf("пара: %+v", rep)
	}
	if len(rep.Added) != 1 || rep.Added[0].Path != "b" {
		t.Fatalf("added: %+v", rep.Added)
	}

	// одиночный прогон — сравнивать не с чем
	if _, ok, err := BetweenLatest(ctx, st, "mongo", nil); err != nil || ok {
		t.Fatalf("один прогон: ok=%v err=%v", ok, err)
	}
	// since отсекает старые прогоны
	since := base.Add(30 * time.Minute)
	if _, ok, err := BetweenLatest(ctx, st, "ch", &since); err != nil || ok {
		t.Fatalf("since: ok=%v err=%v (s1 отсечён — остался один)", ok, err)
	}
}
