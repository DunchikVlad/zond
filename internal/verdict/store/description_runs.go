// Учёт прогонов описания БД (S9-4, blueprint S9 п. 5): история, экономика,
// статусы, аудит. Таблица description_runs (миграция 0013).
package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"time"
)

// DescriptionRun — строка прогона описания БД (S9-4).
type DescriptionRun struct {
	ID            string
	ScanID        string
	Status        string // running|done|failed|interrupted
	PromptVersion string
	PromptHash    string
	AgentID       string
	Model         string
	TokensIn      int
	TokensOut     int
	CostUSD       float64
	LatencyMS     int64
	ResultJSON    string
	Error         string
	CreatedAt     time.Time  `json:"created_at"`
	FinishedAt    *time.Time `json:"finished_at,omitempty"`
}

// NewDescriptionRunID — идентификатор прогона описания: crypto/rand hex(16).
func NewDescriptionRunID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// SaveDescriptionRun создаёт прогон описания.
func (s *Store) SaveDescriptionRun(ctx context.Context, dr *DescriptionRun) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO description_runs (id, scan_id, status, prompt_version, prompt_hash,
			agent_id, model, tokens_in, tokens_out, cost_usd, latency_ms, result_json, error,
			created_at, finished_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		dr.ID, dr.ScanID, dr.Status, dr.PromptVersion, dr.PromptHash,
		dr.AgentID, dr.Model, dr.TokensIn, dr.TokensOut, dr.CostUSD, dr.LatencyMS,
		dr.ResultJSON, dr.Error, dr.CreatedAt.UTC().Format(time.RFC3339), nil)
	return err
}

// FinishDescriptionRun фиксирует завершение прогона описания со статусом.
func (s *Store) FinishDescriptionRun(ctx context.Context, id, status, resultJSON, errMsg string, tokensIn, tokensOut int, costUSD float64, latencyMS int64, finishedAt time.Time) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE description_runs SET status = ?, result_json = ?, error = ?,
			tokens_in = ?, tokens_out = ?, cost_usd = ?, latency_ms = ?, finished_at = ?
		 WHERE id = ?`,
		status, resultJSON, errMsg, tokensIn, tokensOut, costUSD, latencyMS,
		finishedAt.UTC().Format(time.RFC3339), id)
	if err != nil {
		return err
	}
	return requireAffected(res, id)
}

// GetDescriptionRun возвращает прогон описания по ID.
func (s *Store) GetDescriptionRun(ctx context.Context, id string) (*DescriptionRun, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, scan_id, status, prompt_version, prompt_hash, agent_id, model,
			tokens_in, tokens_out, cost_usd, latency_ms, result_json, error, created_at, finished_at
		 FROM description_runs WHERE id = ?`, id)
	return scanDescriptionRun(row)
}

// ListDescriptionRuns возвращает прогоны описания скана (сортировка: свежие первыми).
func (s *Store) ListDescriptionRuns(ctx context.Context, scanID string) ([]DescriptionRun, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, scan_id, status, prompt_version, prompt_hash, agent_id, model,
			tokens_in, tokens_out, cost_usd, latency_ms, result_json, error, created_at, finished_at
		 FROM description_runs WHERE scan_id = ? ORDER BY created_at DESC`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DescriptionRun
	for rows.Next() {
		dr, err := scanDescriptionRunRows(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *dr)
	}
	return out, rows.Err()
}

// scanDescriptionRun — сканирование одной строки description_runs.
func scanDescriptionRun(row *sql.Row) (*DescriptionRun, error) {
	var dr DescriptionRun
	var finishedAt *string
	var createdAt string
	err := row.Scan(&dr.ID, &dr.ScanID, &dr.Status, &dr.PromptVersion, &dr.PromptHash,
		&dr.AgentID, &dr.Model, &dr.TokensIn, &dr.TokensOut, &dr.CostUSD, &dr.LatencyMS,
		&dr.ResultJSON, &dr.Error, &createdAt, &finishedAt)
	if err != nil {
		return nil, err
	}
	dr.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	if finishedAt != nil {
		t, _ := time.Parse(time.RFC3339, *finishedAt)
		dr.FinishedAt = &t
	}
	return &dr, nil
}

// scanDescriptionRunRows — сканирование строки description_runs из rows.
func scanDescriptionRunRows(rows *sql.Rows) (*DescriptionRun, error) {
	var dr DescriptionRun
	var finishedAt *string
	var createdAt string
	err := rows.Scan(&dr.ID, &dr.ScanID, &dr.Status, &dr.PromptVersion, &dr.PromptHash,
		&dr.AgentID, &dr.Model, &dr.TokensIn, &dr.TokensOut, &dr.CostUSD, &dr.LatencyMS,
		&dr.ResultJSON, &dr.Error, &createdAt, &finishedAt)
	if err != nil {
		return nil, err
	}
	dr.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	if finishedAt != nil {
		t, _ := time.Parse(time.RFC3339, *finishedAt)
		dr.FinishedAt = &t
	}
	return &dr, nil
}

// DescriptionRunDTO — DTO для API (S9-4).
func (dr *DescriptionRun) ToDTO() map[string]any {
	dto := map[string]any{
		"id":             dr.ID,
		"scan_id":        dr.ScanID,
		"status":         dr.Status,
		"prompt_version": dr.PromptVersion,
		"prompt_hash":    dr.PromptHash,
		"agent_id":       dr.AgentID,
		"model":          dr.Model,
		"tokens_in":      dr.TokensIn,
		"tokens_out":     dr.TokensOut,
		"cost_usd":       dr.CostUSD,
		"latency_ms":     dr.LatencyMS,
		"created_at":     dr.CreatedAt,
	}
	if dr.FinishedAt != nil {
		dto["finished_at"] = *dr.FinishedAt
	}
	if dr.ResultJSON != "" {
		var result any
		if err := json.Unmarshal([]byte(dr.ResultJSON), &result); err == nil {
			dto["result"] = result
		}
	}
	if dr.Error != "" {
		dto["error"] = dr.Error
	}
	return dto
}
