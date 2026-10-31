// Тесты CRUD и миграции description_runs (S9-4).
package store

import (
	"context"
	"testing"
	"time"
)

func TestDescriptionRunCRUD(t *testing.T) {
	st := openTest(t)
	ctx := context.Background()

	// Создаём scan для FK
	scan := &Scan{ID: "sc1", SourceName: "src", Profile: "p", Status: "done",
		StartedAt: time.Now().UTC(), StatsJSON: "{}"}
	if err := st.SaveScan(ctx, scan); err != nil {
		t.Fatalf("SaveScan: %v", err)
	}

	// Создаём прогон описания
	dr := &DescriptionRun{
		ID: NewDescriptionRunID(), ScanID: "sc1", Status: "running",
		PromptVersion: "1", PromptHash: "abc123",
		AgentID: "agent1", Model: "gpt-4o",
		CreatedAt: time.Now().UTC(),
	}
	if err := st.SaveDescriptionRun(ctx, dr); err != nil {
		t.Fatalf("SaveDescriptionRun: %v", err)
	}

	// Получаем
	got, err := st.GetDescriptionRun(ctx, dr.ID)
	if err != nil {
		t.Fatalf("GetDescriptionRun: %v", err)
	}
	if got.Status != "running" {
		t.Errorf("status = %q, want running", got.Status)
	}
	if got.PromptVersion != "1" {
		t.Errorf("prompt_version = %q, want 1", got.PromptVersion)
	}

	// Финиш успех
	finishedAt := time.Now().UTC()
	resultJSON := `{"purpose_ru":"тест"}`
	if err := st.FinishDescriptionRun(ctx, dr.ID, "done", resultJSON, "", 100, 50, 0.001, 1500, finishedAt); err != nil {
		t.Fatalf("FinishDescriptionRun: %v", err)
	}

	got2, err := st.GetDescriptionRun(ctx, dr.ID)
	if err != nil {
		t.Fatalf("GetDescriptionRun after finish: %v", err)
	}
	if got2.Status != "done" {
		t.Errorf("status = %q, want done", got2.Status)
	}
	if got2.TokensIn != 100 || got2.TokensOut != 50 {
		t.Errorf("tokens = %d/%d, want 100/50", got2.TokensIn, got2.TokensOut)
	}
	if got2.ResultJSON != resultJSON {
		t.Errorf("result_json = %q, want %q", got2.ResultJSON, resultJSON)
	}
	if got2.FinishedAt == nil {
		t.Error("finished_at is nil")
	}

	// Список по scan_id
	runs, err := st.ListDescriptionRuns(ctx, "sc1")
	if err != nil {
		t.Fatalf("ListDescriptionRuns: %v", err)
	}
	if len(runs) != 1 {
		t.Errorf("len(runs) = %d, want 1", len(runs))
	}

	// Финиш ошибка
	dr2 := &DescriptionRun{
		ID: NewDescriptionRunID(), ScanID: "sc1", Status: "running",
		CreatedAt: time.Now().UTC(),
	}
	if err := st.SaveDescriptionRun(ctx, dr2); err != nil {
		t.Fatalf("SaveDescriptionRun 2: %v", err)
	}
	if err := st.FinishDescriptionRun(ctx, dr2.ID, "failed", "", "LLM timeout", 0, 0, 0, 0, finishedAt); err != nil {
		t.Fatalf("FinishDescriptionRun 2: %v", err)
	}
	got3, err := st.GetDescriptionRun(ctx, dr2.ID)
	if err != nil {
		t.Fatalf("GetDescriptionRun 2: %v", err)
	}
	if got3.Status != "failed" {
		t.Errorf("status = %q, want failed", got3.Status)
	}
	if got3.Error != "LLM timeout" {
		t.Errorf("error = %q, want 'LLM timeout'", got3.Error)
	}
}

func TestDescriptionRunMigration0013(t *testing.T) {
	st := openTest(t)
	ctx := context.Background()

	// Проверяем, что таблица существует
	var name string
	err := st.db.QueryRowContext(ctx,
		`SELECT name FROM sqlite_master WHERE type='table' AND name='description_runs'`).Scan(&name)
	if err != nil {
		t.Fatalf("таблица description_runs не создана: %v", err)
	}

	// Проверяем индексы
	var idxName string
	err = st.db.QueryRowContext(ctx,
		`SELECT name FROM sqlite_master WHERE type='index' AND name='idx_description_runs_scan'`).Scan(&idxName)
	if err != nil {
		t.Fatalf("индекс idx_description_runs_scan не создан: %v", err)
	}
}
