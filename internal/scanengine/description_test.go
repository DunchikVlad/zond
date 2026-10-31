// Тесты DescriptionRunner (S9-4): агрегация вердиктов, вызов LLM, статусы,
// аудит, экономика. Без реального LLM — fake DescriptionLLM.
package scanengine

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DunchikVlad/zond/internal/agentproxy"
	"github.com/DunchikVlad/zond/internal/agentproxy/prompts"
	"github.com/DunchikVlad/zond/internal/audit"
	"github.com/DunchikVlad/zond/internal/verdict"
	"github.com/DunchikVlad/zond/internal/verdict/store"
)

// fakeDescriptionLLM — fake LLM для тестов DescriptionRunner.
type fakeDescriptionLLM struct {
	result *agentproxy.DescribeResult
	err    error
	calls  int
	input  string // последний вход
}

func (f *fakeDescriptionLLM) Describe(_ context.Context, input string) (*agentproxy.DescribeResult, error) {
	f.calls++
	f.input = input
	if f.err != nil {
		return nil, f.err
	}
	return f.result, nil
}

func openDescriptionTestStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "desc_test.db"))
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func newDescriptionRunner(st *store.Store, llm DescriptionLLM) *DescriptionRunner {
	return NewDescriptionRunner(st, llm, "agent1", "gpt-4o")
}

func mustScanForDescription(t *testing.T, st *store.Store, id, status string) {
	t.Helper()
	err := st.SaveScan(context.Background(), &store.Scan{
		ID: id, SourceName: "ch-test", Profile: "quick", Status: status,
		StartedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("SaveScan: %v", err)
	}
}

func mustVerdictForDescription(t *testing.T, st *store.Store, scanID, table, path, label string, sens verdict.Sensitivity, conf float64) {
	t.Helper()
	v := verdict.Verdict{
		ID: scanID + ":" + table + ":" + path, ScanID: scanID, Table: table, Path: path,
		NativeType: "String", Label: verdict.Label(label), Sensitivity: sens,
		Confidence: conf, EvidenceLayer: verdict.LayerEnsemble,
		ReviewStatus: verdict.StatusAutoAccepted, CreatedAt: time.Now().UTC(),
	}
	if err := st.SaveVerdicts(context.Background(), []verdict.Verdict{v}); err != nil {
		t.Fatalf("SaveVerdicts: %v", err)
	}
}

func auditFilterDescription(scanID string) audit.Filter {
	return audit.Filter{Category: audit.CatAgent, ScanID: scanID}
}

func TestDescriptionRunnerHappyPath(t *testing.T) {
	st := openDescriptionTestStore(t)
	mustScanForDescription(t, st, "sc1", "done")
	mustVerdictForDescription(t, st, "sc1", "users", "email", "EMAIL", verdict.SensitivityPII, 0.95)
	mustVerdictForDescription(t, st, "sc1", "users", "phone", "PHONE", verdict.SensitivityPII, 0.9)
	mustVerdictForDescription(t, st, "sc1", "orders", "total", "FREE_TEXT", verdict.SensitivityNone, 0.8)

	llm := &fakeDescriptionLLM{
		result: &agentproxy.DescribeResult{
			PurposeRU: "БД клиентских данных",
			TableGroups: []agentproxy.TableGroup{
				{NameRU: "Пользователи", Tables: []string{"users"}, DescriptionRU: "Данные клиентов"},
			},
			DataCategories: []string{"email", "phone"},
			SensitivityZones: agentproxy.SensitivityZones{
				PIITables: []string{"users"}, NoneTables: []string{"orders"},
			},
			Risks:                 []string{"хранение PII"},
			Ambiguities:           []string{},
			ReviewRecommendations: []string{"ревью users"},
			Usage:                 agentproxy.Usage{TokensIn: 500, TokensOut: 200},
			Latency:               2 * time.Second,
		},
	}

	dr := newDescriptionRunner(st, llm)
	run, err := dr.Run(context.Background(), "sc1", "test-actor")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if run.Status != "done" {
		t.Fatalf("status = %q, want done", run.Status)
	}
	if run.ScanID != "sc1" {
		t.Fatalf("scan_id = %q, want sc1", run.ScanID)
	}
	if run.PromptVersion != prompts.DescriptionVersion {
		t.Fatalf("prompt_version = %q, want %q", run.PromptVersion, prompts.DescriptionVersion)
	}
	if run.TokensIn != 500 || run.TokensOut != 200 {
		t.Fatalf("tokens = %d/%d, want 500/200", run.TokensIn, run.TokensOut)
	}
	if llm.calls != 1 {
		t.Fatalf("llm.calls = %d, want 1", llm.calls)
	}
	// Вход содержит агрегированные данные
	if !strings.Contains(llm.input, "users") {
		t.Fatal("вход не содержит таблицу users")
	}
	if !strings.Contains(llm.input, "EMAIL") {
		t.Fatal("вход не содержит лейбл EMAIL")
	}
	// Результат валидный JSON
	var result map[string]any
	if err := json.Unmarshal([]byte(run.ResultJSON), &result); err != nil {
		t.Fatalf("result не JSON: %v", err)
	}
	if result["purpose_ru"] != "БД клиентских данных" {
		t.Fatalf("purpose_ru = %v", result["purpose_ru"])
	}
	// Проверяем аудит
	audits, err := st.AuditList(context.Background(), auditFilterDescription("sc1"))
	if err != nil {
		t.Fatalf("AuditList: %v", err)
	}
	if len(audits) < 2 { // start + finish
		t.Fatalf("аудит-событий %d, want >= 2", len(audits))
	}
}

func TestDescriptionRunnerScanNotFound(t *testing.T) {
	st := openDescriptionTestStore(t)
	dr := newDescriptionRunner(st, &fakeDescriptionLLM{})
	_, err := dr.Run(context.Background(), "nonexistent", "test")
	if err == nil {
		t.Fatal("ожидалась ошибка")
	}
}

func TestDescriptionRunnerNotTerminal(t *testing.T) {
	st := openDescriptionTestStore(t)
	mustScanForDescription(t, st, "sc1", "running")
	dr := newDescriptionRunner(st, &fakeDescriptionLLM{})
	_, err := dr.Run(context.Background(), "sc1", "test")
	if err == nil {
		t.Fatal("ожидалась ошибка: running не терминальный")
	}
	if !strings.Contains(err.Error(), "терминальный") {
		t.Fatalf("ошибка = %v, want 'терминальный'", err)
	}
}

func TestDescriptionRunnerNoLLM(t *testing.T) {
	st := openDescriptionTestStore(t)
	mustScanForDescription(t, st, "sc1", "done")
	dr := newDescriptionRunner(st, nil)
	_, err := dr.Run(context.Background(), "sc1", "test")
	if err == nil {
		t.Fatal("ожидалась ошибка: LLM не подключён")
	}
}

func TestDescriptionRunnerLLMError(t *testing.T) {
	st := openDescriptionTestStore(t)
	mustScanForDescription(t, st, "sc1", "done")
	mustVerdictForDescription(t, st, "sc1", "users", "email", "EMAIL", verdict.SensitivityPII, 0.9)

	llm := &fakeDescriptionLLM{err: errors.New("LLM timeout")}
	dr := newDescriptionRunner(st, llm)
	run, err := dr.Run(context.Background(), "sc1", "test-actor")
	if err == nil {
		t.Fatal("ожидалась ошибка LLM")
	}
	if run != nil {
		t.Fatal("run должен быть nil при ошибке")
	}
	// Проверяем, что запись в store получила статус failed
	runs, _ := st.ListDescriptionRuns(context.Background(), "sc1")
	if len(runs) != 1 {
		t.Fatalf("runs = %d, want 1", len(runs))
	}
	if runs[0].Status != "failed" {
		t.Fatalf("status = %q, want failed", runs[0].Status)
	}
	if runs[0].Error == "" {
		t.Fatal("error пуст")
	}
}

func TestDescriptionRunnerPartialMarked(t *testing.T) {
	st := openDescriptionTestStore(t)
	mustScanForDescription(t, st, "sc1", "partial")
	mustVerdictForDescription(t, st, "sc1", "users", "email", "EMAIL", verdict.SensitivityPII, 0.9)

	llm := &fakeDescriptionLLM{
		result: &agentproxy.DescribeResult{
			PurposeRU: "Частичное описание",
			TableGroups: []agentproxy.TableGroup{
				{NameRU: "Г", Tables: []string{"users"}, DescriptionRU: "О"},
			},
			DataCategories:        []string{"email"},
			SensitivityZones:      agentproxy.SensitivityZones{PIITables: []string{"users"}},
			Risks:                 []string{},
			Ambiguities:           []string{},
			ReviewRecommendations: []string{},
		},
	}
	dr := newDescriptionRunner(st, llm)
	run, err := dr.Run(context.Background(), "sc1", "test-actor")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if run.Status != "done" {
		t.Fatalf("status = %q, want done", run.Status)
	}
	// Вход содержит пометку PARTIAL
	if !strings.Contains(llm.input, "PARTIAL_SCAN") {
		t.Fatal("вход не содержит пометку PARTIAL_SCAN")
	}
}

func TestDescriptionRunnerNoVerdicts(t *testing.T) {
	st := openDescriptionTestStore(t)
	mustScanForDescription(t, st, "sc1", "done")
	// Нет вердиктов
	dr := newDescriptionRunner(st, &fakeDescriptionLLM{})
	_, err := dr.Run(context.Background(), "sc1", "test")
	if err == nil {
		t.Fatal("ожидалась ошибка: нет вердиктов")
	}
}

func TestDescriptionRunnerAggregation(t *testing.T) {
	st := openDescriptionTestStore(t)
	mustScanForDescription(t, st, "sc1", "done")
	mustVerdictForDescription(t, st, "sc1", "t1", "c1", "EMAIL", verdict.SensitivityPII, 0.9)
	mustVerdictForDescription(t, st, "sc1", "t1", "c2", "PHONE", verdict.SensitivityPII, 0.8)
	mustVerdictForDescription(t, st, "sc1", "t2", "c3", "CARD", verdict.SensitivityPCI, 0.95)

	llm := &fakeDescriptionLLM{
		result: &agentproxy.DescribeResult{
			PurposeRU: "Тест",
			TableGroups: []agentproxy.TableGroup{
				{NameRU: "Г", Tables: []string{"t1", "t2"}, DescriptionRU: "О"},
			},
			DataCategories: []string{"email", "phone", "card"},
			SensitivityZones: agentproxy.SensitivityZones{
				PIITables: []string{"t1"}, PCITables: []string{"t2"},
			},
			Risks:                 []string{},
			Ambiguities:           []string{},
			ReviewRecommendations: []string{},
		},
	}
	dr := newDescriptionRunner(st, llm)
	_, err := dr.Run(context.Background(), "sc1", "test")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// Вход содержит обе таблицы
	if !strings.Contains(llm.input, "t1") || !strings.Contains(llm.input, "t2") {
		t.Fatal("вход не содержит обе таблицы")
	}
	// Вход — валидный JSON
	var input map[string]any
	if err := json.Unmarshal([]byte(llm.input), &input); err != nil {
		t.Fatalf("вход не JSON: %v", err)
	}
	tables := input["tables"].([]any)
	if len(tables) != 2 {
		t.Fatalf("tables = %d, want 2", len(tables))
	}
}
