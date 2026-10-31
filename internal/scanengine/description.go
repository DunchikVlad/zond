// DescriptionRunner — отдельный агентский прогон описания БД по scan_id (S9-4).
// Без повторного подключения к источнику: агрегирует вердикты скана и вызывает
// LLM через agentproxy. Статусы running|done|failed|interrupted, история,
// экономика, аудит. Агрегированный вход — только лейблы/типы/sensitivity,
// без сырых значений и имён инфраструктуры (ADR изоляции).
package scanengine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/DunchikVlad/zond/internal/agentproxy"
	"github.com/DunchikVlad/zond/internal/agentproxy/prompts"
	"github.com/DunchikVlad/zond/internal/audit"
	"github.com/DunchikVlad/zond/internal/verdict/store"
)

// DescriptionLLM — интерфейс LLM для описания БД (S9-4).
// Реализуется agentproxy.Proxy; в тестах — fake.
type DescriptionLLM interface {
	Describe(ctx context.Context, input string) (*agentproxy.DescribeResult, error)
}

// DescriptionRunner — оркестратор агентского прогона описания БД (S9-4).
type DescriptionRunner struct {
	st      *store.Store
	llm     DescriptionLLM
	agentID string
	model   string
	nowFn   func() time.Time
}

// NewDescriptionRunner собирает runner: store + прокси к LLM.
func NewDescriptionRunner(st *store.Store, llm DescriptionLLM, agentID, model string) *DescriptionRunner {
	return &DescriptionRunner{st: st, llm: llm, agentID: agentID, model: model, nowFn: time.Now}
}

// Run запускает прогон описания БД по scan_id. Блокирует до завершения.
// Требования: scan в терминальном статусе (done/partial/failed/budget_exceeded);
// partial — с явной пометкой неполного снимка. LLM должен быть подключен.
func (r *DescriptionRunner) Run(ctx context.Context, scanID, actor string) (*store.DescriptionRun, error) {
	if r.llm == nil {
		return nil, errors.New("description: LLM не подключён")
	}

	// Проверяем скан
	sc, err := r.st.GetScan(ctx, scanID)
	if err != nil {
		return nil, fmt.Errorf("description: скан %s: %w", scanID, err)
	}
	if !isTerminalScanStatus(sc.Status) {
		return nil, fmt.Errorf("description: скан %s в статусе %q, нужен терминальный", scanID, sc.Status)
	}

	// Агрегируем вердикты
	input, err := r.aggregate(ctx, scanID, sc.Status)
	if err != nil {
		return nil, fmt.Errorf("description: агрегация: %w", err)
	}

	// Создаём запись
	dr := &store.DescriptionRun{
		ID:            store.NewDescriptionRunID(),
		ScanID:        scanID,
		Status:        "running",
		PromptVersion: prompts.DescriptionVersion,
		PromptHash:    prompts.DescriptionHash(input),
		AgentID:       r.agentID,
		Model:         r.model,
		CreatedAt:     r.nowFn().UTC(),
	}
	if err := r.st.SaveDescriptionRun(ctx, dr); err != nil {
		return nil, fmt.Errorf("description: сохранение: %w", err)
	}

	// Аудит старта (fail-closed)
	if err := r.st.AppendAudit(ctx, []audit.Event{{
		Actor: actor, Category: audit.CatAgent, Action: "description_start",
		Target: "description_run:" + dr.ID,
		Details: map[string]any{
			"scan_id": scanID, "agent_id": r.agentID, "model": r.model,
			"prompt_version": dr.PromptVersion, "prompt_hash": dr.PromptHash,
			"partial": sc.Status != "done",
		},
		TS: r.nowFn().UTC(),
	}}); err != nil {
		return nil, fmt.Errorf("description: аудит старта: %w", err)
	}

	// Вызов LLM
	result, err := r.llm.Describe(ctx, input)
	finishedAt := r.nowFn().UTC()

	if err != nil {
		// Прерывание контекста — особый статус
		status := "failed"
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			status = "interrupted"
		}
		errMsg := truncateDescriptionErr(err.Error(), 300)
		if finishErr := r.st.FinishDescriptionRun(ctx, dr.ID, status, "", errMsg,
			0, 0, 0, 0, finishedAt); finishErr != nil {
			return nil, fmt.Errorf("description: фиксация ошибки: %w", finishErr)
		}
		// Аудит ошибки
		_ = r.st.AppendAudit(ctx, []audit.Event{{
			Actor: actor, Category: audit.CatAgent, Action: "description_failed",
			Target: "description_run:" + dr.ID,
			Details: map[string]any{
				"scan_id": scanID, "error": errMsg, "status": status,
			},
			TS: r.nowFn().UTC(),
		}})
		return nil, fmt.Errorf("description: вызов LLM: %w", err)
	}

	// Успех: сериализуем результат
	resultJSON, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("description: сериализация результата: %w", err)
	}

	// Стоимость по прайс-листу
	cost := r.costFor(result.Usage)

	// Финиш
	if err := r.st.FinishDescriptionRun(ctx, dr.ID, "done", string(resultJSON), "",
		result.Usage.TokensIn, result.Usage.TokensOut, cost, result.Latency.Milliseconds(), finishedAt); err != nil {
		return nil, fmt.Errorf("description: фиксация успеха: %w", err)
	}

	// Аудит успеха
	_ = r.st.AppendAudit(ctx, []audit.Event{{
		Actor: actor, Category: audit.CatAgent, Action: "description_finish",
		Target: "description_run:" + dr.ID,
		Details: map[string]any{
			"scan_id": scanID, "tokens_in": result.Usage.TokensIn,
			"tokens_out": result.Usage.TokensOut, "cost_usd": cost,
			"latency_ms": result.Latency.Milliseconds(),
		},
		TS: r.nowFn().UTC(),
	}})

	dr.Status = "done"
	dr.ResultJSON = string(resultJSON)
	dr.TokensIn = result.Usage.TokensIn
	dr.TokensOut = result.Usage.TokensOut
	dr.CostUSD = cost
	dr.LatencyMS = result.Latency.Milliseconds()
	dr.FinishedAt = &finishedAt
	return dr, nil
}

// aggregate собирает агрегированный вход из вердиктов скана (S9-4).
// Только лейблы/типы/sensitivity/confidence — без сырых значений.
// Для partial-скана — явная пометка неполного снимка.
func (r *DescriptionRunner) aggregate(ctx context.Context, scanID, scanStatus string) (string, error) {
	verdicts, err := r.st.ListVerdicts(ctx, scanID)
	if err != nil {
		return "", fmt.Errorf("вердикты: %w", err)
	}
	if len(verdicts) == 0 {
		return "", errors.New("нет вердиктов для описания")
	}

	// Группируем по таблицам
	tables := map[string][]prompts.DescriptionColumn{}
	for _, v := range verdicts {
		col := prompts.DescriptionColumn{
			Path:        v.Path,
			NativeType:  v.NativeType,
			Label:       string(v.Label),
			Sensitivity: string(v.Sensitivity),
			Confidence:  v.Confidence,
		}
		tables[v.Table] = append(tables[v.Table], col)
	}

	// Формируем вход
	input := prompts.DescriptionInput{}
	for name, cols := range tables {
		t := prompts.DescriptionTable{Name: name, Columns: cols}
		input.Tables = append(input.Tables, t)
	}

	// Пометка partial-скана
	if scanStatus != "done" {
		// Добавляем префикс-предупреждение
		var b strings.Builder
		b.WriteString("PARTIAL_SCAN: этот снимок неполный (статус ")
		b.WriteString(scanStatus)
		b.WriteString("). ")
		b.WriteString("Некоторые таблицы могут отсутствовать.\n")
		data, err := json.Marshal(input)
		if err != nil {
			return "", fmt.Errorf("сериализация входа: %w", err)
		}
		b.Write(data)
		return b.String(), nil
	}

	data, err := json.Marshal(input)
	if err != nil {
		return "", fmt.Errorf("сериализация входа: %w", err)
	}
	return string(data), nil
}

// costFor — стоимость вызова по прайс-листу (п. 10.6).
func (r *DescriptionRunner) costFor(usage agentproxy.Usage) float64 {
	per1mIn, per1mOut, ok := r.st.PriceFor(context.Background(), r.model, r.nowFn())
	if !ok {
		return 0
	}
	cost := float64(usage.TokensIn)/1e6*per1mIn + float64(usage.TokensOut)/1e6*per1mOut
	return float64(int(cost*1e6)) / 1e6 // округление до 6 знаков
}

// isTerminalScanStatus — скан в терминальном статусе (можно описывать).
func isTerminalScanStatus(s string) bool {
	switch s {
	case "done", "partial", "failed", "budget_exceeded":
		return true
	}
	return false
}

// truncateDescriptionErr обрезает текст ошибки для description_runs.
func truncateDescriptionErr(s string, max int) string {
	if len([]rune(s)) <= max {
		return s
	}
	return string([]rune(s)[:max]) + "…"
}

// DescriptionRunnerInterface — интерфейс для API (внедрение зависимости).
type DescriptionRunnerInterface interface {
	Run(ctx context.Context, scanID, actor string) (*store.DescriptionRun, error)
}
