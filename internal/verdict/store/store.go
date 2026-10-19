// Package store — Verdict Store на SQLite (ADR-0006, blueprint п. 11.1):
// modernc.org/sqlite (чистый Go, без cgo), миграции goose embed-ятся
// в бинарник. Этап 1: таблицы scans/scan_tables/verdicts; инкремент 4б —
// verdict_cache; инкремент 4в — agent_calls + model_prices (п. 10.6).
// Полная схема п. 11.1 (audit_log, review_events, …) — этап 5.
package store

import (
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"time"

	"github.com/DunchikVlad/zond/internal/verdict"
	"github.com/pressly/goose/v3"
	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

func init() {
	goose.SetBaseFS(migrationsFS)
	// логи goose (OK xxx.sql) — шум для структурированного логирования (ADR-0013)
	goose.SetLogger(log.New(io.Discard, "", 0))
}

// Store — SQLite-хранилище вердиктов.
type Store struct {
	db *sql.DB
}

// Open открывает (при необходимости создаёт) файл БД и накатывает миграции.
func Open(path string) (*Store, error) {
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlite open: %w", err)
	}
	db.SetMaxOpenConns(1) // один писатель — этот процесс (упрощение п. 11.1 до этапа 5)
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("sqlite ping: %w", err)
	}
	if err := goose.SetDialect("sqlite3"); err != nil {
		db.Close()
		return nil, err
	}
	if err := goose.Up(db, "migrations"); err != nil {
		db.Close()
		return nil, fmt.Errorf("миграции: %w", err)
	}
	return &Store{db: db}, nil
}

// Close закрывает БД.
func (s *Store) Close() error { return s.db.Close() }

// Ping проверяет доступность БД (readiness API, п. 11.2 /api/ready).
func (s *Store) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }

// ---------------------------------------------------------------------------
// scans / scan_tables — чекпоинты прогона (blueprint п. 13)
// ---------------------------------------------------------------------------

// Scan — строка прогона сканирования.
type Scan struct {
	ID         string
	SourceName string
	Profile    string
	Status     string // running|partial|done|interrupted|failed|budget_exceeded
	StartedAt  time.Time
	FinishedAt *time.Time
	StatsJSON  string
}

// SaveScan создаёт прогон.
func (s *Store) SaveScan(ctx context.Context, sc *Scan) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO scans (id, source_name, profile, status, started_at, stats_json)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		sc.ID, sc.SourceName, sc.Profile, sc.Status, sc.StartedAt.UTC().Format(time.RFC3339), sc.StatsJSON)
	return err
}

// FinishScan фиксирует завершение прогона со статусом.
func (s *Store) FinishScan(ctx context.Context, id, status, statsJSON string, finishedAt time.Time) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE scans SET status = ?, finished_at = ?, stats_json = ? WHERE id = ?`,
		status, finishedAt.UTC().Format(time.RFC3339), statsJSON, id)
	if err != nil {
		return err
	}
	return requireAffected(res, id)
}

// MarkTable — чекпоинт таблицы внутри прогона (blueprint п. 13).
func (s *Store) MarkTable(ctx context.Context, scanID, table string, rowCount int64, status, errMsg string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO scan_tables (scan_id, table_name, row_count, status, error)
		 VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT (scan_id, table_name) DO UPDATE SET
		   row_count = excluded.row_count, status = excluded.status, error = excluded.error`,
		scanID, table, rowCount, status, errMsg)
	return err
}

// ---------------------------------------------------------------------------
// verdicts
// ---------------------------------------------------------------------------

// ListVerdicts возвращает вердикты прогона.
func (s *Store) ListVerdicts(ctx context.Context, scanID string) ([]verdict.Verdict, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, scan_id, table_name, path, native_type, label, sensitivity, confidence,
		       evidence_layer, evidence, taxonomy_version, detectors_version, prompt_version,
		       sample_size, cluster_id, review_status, final_label, reviewed_by, reviewed_at, created_at
		FROM verdicts WHERE scan_id = ? ORDER BY table_name, path`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []verdict.Verdict
	for rows.Next() {
		v, err := scanVerdict(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanVerdict(r rowScanner) (verdict.Verdict, error) {
	var v verdict.Verdict
	var ev, createdAt, reviewedAt string
	err := r.Scan(&v.ID, &v.ScanID, &v.Table, &v.Path, &v.NativeType, &v.Label, &v.Sensitivity,
		&v.Confidence, &v.EvidenceLayer, &ev, &v.TaxonomyVersion, &v.DetectorsVersion,
		&v.PromptVersion, &v.SampleSize, &v.ClusterID, &v.ReviewStatus, &v.FinalLabel,
		&v.ReviewedBy, &reviewedAt, &createdAt)
	if err != nil {
		return v, err
	}
	v.Evidence = map[string]any{}
	if ev != "" {
		if err := json.Unmarshal([]byte(ev), &v.Evidence); err != nil {
			return v, fmt.Errorf("verdict %s: evidence: %w", v.ID, err)
		}
	}
	v.ReviewedAt, _ = time.Parse(time.RFC3339, reviewedAt)
	v.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	return v, nil
}

// Summary — агрегаты прогона для отчёта.
type Summary struct {
	Total    int
	ByStatus map[string]int
	ByLabel  map[string]int
	ByLayer  map[string]int
}

// VerdictSummary считает агрегаты по вердиктам прогона.
func (s *Store) VerdictSummary(ctx context.Context, scanID string) (*Summary, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT review_status, label, evidence_layer, COUNT(*) FROM verdicts WHERE scan_id = ? GROUP BY 1, 2, 3`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	sum := &Summary{ByStatus: map[string]int{}, ByLabel: map[string]int{}, ByLayer: map[string]int{}}
	for rows.Next() {
		var status, label, layer string
		var n int
		if err := rows.Scan(&status, &label, &layer, &n); err != nil {
			return nil, err
		}
		sum.Total += n
		sum.ByStatus[status] += n
		sum.ByLabel[label] += n
		sum.ByLayer[layer] += n
	}
	return sum, rows.Err()
}

// FailedTables — таблицы прогона со статусом failed (для отчёта).
func (s *Store) FailedTables(ctx context.Context, scanID string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT table_name || ': ' || error FROM scan_tables WHERE scan_id = ? AND status = 'failed' ORDER BY table_name`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func requireAffected(res sql.Result, id string) error {
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("запись %s не найдена", id)
	}
	return nil
}
