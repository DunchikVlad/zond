// Тесты retention сканов (blueprint п. 15.4): PurgeScansOlderThan удаляет
// старый прогон со всеми связанными данными одной транзакцией, свежий не
// трогает, running-прогоны (без finished_at) — не трогает.
package store

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/DunchikVlad/zond/internal/verdict"
)

func mustSaveFinishedScan(t *testing.T, st *Store, id, source string, finishedAt time.Time) {
	t.Helper()
	ctx := context.Background()
	if err := st.SaveScan(ctx, &Scan{ID: id, SourceName: source, Profile: "quick",
		Status: "running", StartedAt: finishedAt.Add(-time.Hour)}); err != nil {
		t.Fatalf("SaveScan %s: %v", id, err)
	}
	if err := st.FinishScan(ctx, id, "done", "{}", finishedAt); err != nil {
		t.Fatalf("FinishScan %s: %v", id, err)
	}
}

func scanExists(t *testing.T, st *Store, id string) bool {
	t.Helper()
	_, err := st.GetScan(context.Background(), id)
	if errors.Is(err, sql.ErrNoRows) {
		return false
	}
	if err != nil {
		t.Fatalf("GetScan %s: %v", id, err)
	}
	return true
}

func TestPurgeScansOlderThan(t *testing.T) {
	st, err := Open(t.TempDir() + "/retention.db")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer st.Close()
	ctx := context.Background()
	now := time.Now().UTC()
	cutoff := now.Add(-90 * 24 * time.Hour)

	// Старый прогон с вердиктами, вызовами агентов и чекпоинтом таблицы.
	mustSaveFinishedScan(t, st, "old-1", "ch", now.Add(-91*24*time.Hour))
	if err := st.MarkTable(ctx, "old-1", "users", 100, "done", "", ""); err != nil {
		t.Fatalf("MarkTable: %v", err)
	}
	vOld := verdict.Verdict{ID: "old-v1", ScanID: "old-1", Table: "users", Path: "email",
		NativeType: "String", Label: "EMAIL", Sensitivity: "PII", Confidence: 0.9,
		EvidenceLayer: verdict.LayerRules, Evidence: map[string]any{}, ReviewStatus: verdict.StatusPending,
		CreatedAt: now}
	call := AgentCall{ID: "c1", ScanID: "old-1", VerdictID: "old-v1", AgentID: "a",
		Model: "m", TokensIn: 10, TokensOut: 5, Status: "ok", CreatedAt: now}
	if err := st.SaveVerdictsWithCalls(ctx, []verdict.Verdict{vOld}, []AgentCall{call}, nil); err != nil {
		t.Fatalf("SaveVerdictsWithCalls: %v", err)
	}

	// Свежий прогон и running-прогон (finished_at пустой) — не трогаем.
	mustSaveFinishedScan(t, st, "fresh-1", "ch", now.Add(-24*time.Hour))
	if err := st.SaveScan(ctx, &Scan{ID: "run-1", SourceName: "ch", Profile: "quick",
		Status: "running", StartedAt: now}); err != nil {
		t.Fatalf("SaveScan running: %v", err)
	}

	removed, err := st.PurgeScansOlderThan(ctx, cutoff)
	if err != nil {
		t.Fatalf("PurgeScansOlderThan: %v", err)
	}
	if removed != 1 {
		t.Fatalf("removed=%d, ожидался 1", removed)
	}
	if scanExists(t, st, "old-1") {
		t.Fatal("старый прогон не удалён")
	}
	if !scanExists(t, st, "fresh-1") || !scanExists(t, st, "run-1") {
		t.Fatal("свежий/running прогон удалён")
	}
	if _, err := st.GetVerdict(ctx, "old-v1"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("вердикт старого прогона: %v", err)
	}
	calls, err := st.ListAgentCalls(ctx, "old-1")
	if err != nil {
		t.Fatalf("ListAgentCalls: %v", err)
	}
	if len(calls) != 0 {
		t.Fatalf("agent_calls старого прогона не удалены: %d", len(calls))
	}
	if tbl, _ := st.ScanTables(ctx, "old-1"); len(tbl) != 0 {
		t.Fatalf("scan_tables старого прогона не удалены: %d", len(tbl))
	}
	// Повторная прочистка — no-op, ошибок нет.
	if removed, err := st.PurgeScansOlderThan(ctx, cutoff); err != nil || removed != 0 {
		t.Fatalf("повторная прочистка: removed=%d err=%v", removed, err)
	}
}

func TestPurgeScansOlderThanEmpty(t *testing.T) {
	st, err := Open(t.TempDir() + "/retention-empty.db")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer st.Close()
	removed, err := st.PurgeScansOlderThan(context.Background(), time.Now().UTC())
	if err != nil || removed != 0 {
		t.Fatalf("пустой store: removed=%d err=%v", removed, err)
	}
}
