// Учёт LLM-вызовов (blueprint п. 10.6, п. 11.1) и прайс-лист моделей.
// Каждая строка agent_calls соответствует одному вызову (или попаданию в кэш)
// и пишется в одной транзакции с вердиктом (п. 13).
package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/DunchikVlad/zond/internal/audit"
	"github.com/DunchikVlad/zond/internal/verdict"
)

// Операции агента (S9-2): classify — классификатор серого коридора,
// verify — эскалация в верификатор (п. 7 правило 4).
const (
	CallOpClassify = "classify"
	CallOpVerify   = "verify"
)

// AgentCall — учётная запись одного обращения к LLM-слою (п. 10.6).
// S9-2: расширена ответом агента (лейбл/уверенность/чувствительность),
// объяснением reason_ru и текстом ошибки — полный per-column evidence.
type AgentCall struct {
	ID                string
	ScanID            string
	VerdictID         string // вердикт колонки, породившей вызов (FK, п. 13)
	AgentID           string
	Model             string
	Operation         string // classify | verify (S9-2)
	PromptVersion     string
	TokensIn          int
	TokensOut         int
	CostUSD           float64
	LatencyMS         int64
	Cached            bool    // true — вердикт из кэша (п. 10.5), без сетевого вызова
	Status            string  // ok | error | cache_hit
	AnswerLabel       string  // S9-2: лейбл из ответа агента
	AnswerConfidence  float64 // S9-2: уверенность из ответа агента
	AnswerSensitivity string  // S9-2: чувствительность из ответа агента
	ReasonRU          string  // S9-2: объяснение агента (причина вердикта)
	Error             string  // S9-2: текст ошибки вызова (обрезан до 300 симв.)
	CreatedAt         time.Time
}

// NewCallID — идентификатор учётной записи вызова: crypto/rand hex(16).
func NewCallID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// SaveVerdictsWithCalls атомарно сохраняет вердикты, учётные записи вызовов
// и аудит-события таблицы в ОДНОЙ транзакции (blueprint п. 13, п. 14.2):
// либо всё вместе, либо откат — «висящих» вердиктов без учётной записи и
// действий без аудита быть не должно. events — пустой срез = без аудита.
func (s *Store) SaveVerdictsWithCalls(ctx context.Context, vs []verdict.Verdict, calls []AgentCall, events []audit.Event) error {
	if len(vs) == 0 && len(calls) == 0 && len(events) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	// Rollback после Commit вернёт sql.ErrTxDone — безопасно игнорировать.
	defer func() { _ = tx.Rollback() }()
	if len(vs) > 0 {
		if err := insertVerdicts(ctx, tx, vs); err != nil {
			return err
		}
	}
	if len(calls) > 0 {
		if err := insertAgentCalls(ctx, tx, calls); err != nil {
			return err
		}
	}
	if len(events) > 0 {
		if err := audit.AppendTx(ctx, tx, events); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// SaveVerdicts атомарно сохраняет вердикты; повторная вставка того же id
// заменяет запись (идемпотентность, blueprint п. 5.4/п. 13). Обёртка над
// SaveVerdictsWithCalls без учётных записей и аудита — API этапа 1 сохранён.
func (s *Store) SaveVerdicts(ctx context.Context, vs []verdict.Verdict) error {
	return s.SaveVerdictsWithCalls(ctx, vs, nil, nil)
}

// insertVerdicts — вставка вердиктов внутри транзакции (было телом SaveVerdicts).
func insertVerdicts(ctx context.Context, tx *sql.Tx, vs []verdict.Verdict) error {
	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO verdicts (id, scan_id, table_name, path, native_type, label, sensitivity,
		  confidence, evidence_layer, evidence, taxonomy_version, detectors_version, prompt_version,
		  sample_size, cluster_id, llm_status, review_status, final_label, reviewed_by, reviewed_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (id) DO UPDATE SET
		  label = excluded.label, sensitivity = excluded.sensitivity,
		  confidence = excluded.confidence, evidence_layer = excluded.evidence_layer,
		  evidence = excluded.evidence, review_status = excluded.review_status,
		  llm_status = excluded.llm_status,
		  sample_size = excluded.sample_size, created_at = excluded.created_at`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for i := range vs {
		v := &vs[i]
		ev, err := json.Marshal(v.Evidence)
		if err != nil {
			return fmt.Errorf("verdict %s: evidence: %w", v.ID, err)
		}
		_, err = stmt.ExecContext(ctx, v.ID, v.ScanID, v.Table, v.Path, v.NativeType,
			string(v.Label), string(v.Sensitivity), v.Confidence, string(v.EvidenceLayer),
			string(ev), v.TaxonomyVersion, v.DetectorsVersion, v.PromptVersion,
			v.SampleSize, v.ClusterID, string(v.LLMStatus), string(v.ReviewStatus), string(v.FinalLabel),
			v.ReviewedBy, v.ReviewedAt.UTC().Format(time.RFC3339),
			v.CreatedAt.UTC().Format(time.RFC3339))
		if err != nil {
			return fmt.Errorf("verdict %s: %w", v.ID, err)
		}
	}
	return nil
}

// insertAgentCalls — вставка учётных записей внутри транзакции (п. 10.6).
// Нарушение FK (verdict_id/scan_id) откатывает всю транзакцию (п. 13).
func insertAgentCalls(ctx context.Context, tx *sql.Tx, calls []AgentCall) error {
	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO agent_calls (id, scan_id, verdict_id, agent_id, model, prompt_version,
		  tokens_in, tokens_out, cost_usd, latency_ms, cached, status,
		  operation, answer_label, answer_confidence, answer_sensitivity, reason_ru, error, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for i := range calls {
		c := &calls[i]
		cached := 0
		if c.Cached {
			cached = 1
		}
		_, err = stmt.ExecContext(ctx, c.ID, c.ScanID, c.VerdictID, c.AgentID, c.Model,
			c.PromptVersion, c.TokensIn, c.TokensOut, c.CostUSD, c.LatencyMS, cached, c.Status,
			c.Operation, c.AnswerLabel, c.AnswerConfidence, c.AnswerSensitivity, c.ReasonRU, c.Error,
			c.CreatedAt.UTC().Format(time.RFC3339))
		if err != nil {
			return fmt.Errorf("agent_call %s: %w", c.ID, err)
		}
	}
	return nil
}

// callSelectColumns — полный список колонок agent_calls (S9-2: ответ агента,
// объяснение, ошибка) для всех выборок учётных записей.
const callSelectColumns = `id, scan_id, verdict_id, agent_id, model, prompt_version,
	tokens_in, tokens_out, cost_usd, latency_ms, cached, status,
	operation, answer_label, answer_confidence, answer_sensitivity, reason_ru, error, created_at`

// scanAgentCall — сканирование строки agent_calls по callSelectColumns.
func scanAgentCall(rows *sql.Rows) (AgentCall, error) {
	var c AgentCall
	var cached int
	var created string
	if err := rows.Scan(&c.ID, &c.ScanID, &c.VerdictID, &c.AgentID, &c.Model, &c.PromptVersion,
		&c.TokensIn, &c.TokensOut, &c.CostUSD, &c.LatencyMS, &cached, &c.Status,
		&c.Operation, &c.AnswerLabel, &c.AnswerConfidence, &c.AnswerSensitivity, &c.ReasonRU, &c.Error,
		&created); err != nil {
		return c, err
	}
	c.Cached = cached != 0
	c.CreatedAt, _ = time.Parse(time.RFC3339, created)
	return c, nil
}

// ListAgentCalls возвращает учётные записи прогона (п. 10.6) — для тестов,
// валидации и метрик п. 17 (доля кэша, латентность, стоимость).
func (s *Store) ListAgentCalls(ctx context.Context, scanID string) ([]AgentCall, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT `+callSelectColumns+`
		FROM agent_calls WHERE scan_id = ? ORDER BY created_at, id`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AgentCall
	for rows.Next() {
		c, err := scanAgentCall(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ListAgentCallsByVerdict — учётные записи одного вердикта (S9-2: per-column
// evidence вызовов для карточки колонки), в хронологическом порядке.
func (s *Store) ListAgentCallsByVerdict(ctx context.Context, verdictID string) ([]AgentCall, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT `+callSelectColumns+`
		FROM agent_calls WHERE verdict_id = ? ORDER BY created_at, id`, verdictID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AgentCall
	for rows.Next() {
		c, err := scanAgentCall(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// PriceFor возвращает цену модели за 1M токенов (in/out), действующую на момент
// now: последняя запись с effective_from <= now. Модель не найдена → ok=false
// (вызов учитывается с cost_usd=0; прайс-лист пополняется вручную, п. 11.1).
func (s *Store) PriceFor(ctx context.Context, model string, now time.Time) (per1mIn, per1mOut float64, ok bool) {
	row := s.db.QueryRowContext(ctx,
		`SELECT per_1m_in, per_1m_out FROM model_prices
		 WHERE model = ? AND effective_from <= ?
		 ORDER BY effective_from DESC LIMIT 1`,
		model, now.UTC().Format(time.RFC3339))
	if err := row.Scan(&per1mIn, &per1mOut); err != nil {
		return 0, 0, false
	}
	return per1mIn, per1mOut, true
}
