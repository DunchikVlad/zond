// Выборки по сканам для REST API (blueprint п. 11.2): список прогонов с
// фильтрами и пагинацией, карточка прогона с прогрессом по таблицам.
package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// ScanFilter — фильтры списка прогонов (GET /api/v1/scans).
type ScanFilter struct {
	Status string // running|partial|done|interrupted|failed|budget_exceeded; "" — все
	Source string // имя источника; "" — все
	Limit  int    // 0 → default 50; верхняя граница — MaxPageLimit
	Offset int    // <0 трактуется как 0
}

// MaxPageLimit — верхняя граница page size для всех списочных выборок API.
const MaxPageLimit = 500

func normalizePage(limit, offset, def int) (int, int) {
	if limit <= 0 {
		limit = def
	}
	if limit > MaxPageLimit {
		limit = MaxPageLimit
	}
	if offset < 0 {
		offset = 0
	}
	return limit, offset
}

const scanSelectColumns = `id, source_name, profile, status, started_at, finished_at, stats_json,
	table_identity_version, config_fingerprint, taxonomy_version, detectors_version, binary_version`

// ListScans возвращает прогоны по фильтру (сортировка: свежие первыми) и
// общее число строк под фильтром (для пагинации UI).
func (s *Store) ListScans(ctx context.Context, f ScanFilter) ([]Scan, int, error) {
	limit, offset := normalizePage(f.Limit, f.Offset, 50)
	where := ""
	var args []any
	if f.Status != "" {
		where += " AND status = ?"
		args = append(args, f.Status)
	}
	if f.Source != "" {
		where += " AND source_name = ?"
		args = append(args, f.Source)
	}
	if where != "" {
		where = " WHERE " + where[5:]
	}
	var total int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM scans`+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	q := `SELECT ` + scanSelectColumns + `
	      FROM scans` + where + ` ORDER BY started_at DESC, id DESC LIMIT ? OFFSET ?`
	rows, err := s.db.QueryContext(ctx, q, append(args, limit, offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []Scan
	for rows.Next() {
		sc, err := scanScanRow(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, sc)
	}
	return out, total, rows.Err()
}

// GetScan возвращает прогон по id; sql.ErrNoRows, если не найден
// (API отображает в scan_not_found, п. 11.2).
func (s *Store) GetScan(ctx context.Context, id string) (*Scan, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT `+scanSelectColumns+`
		FROM scans WHERE id = ?`, id)
	sc, err := scanScanRow(row)
	if err != nil {
		return nil, err
	}
	return &sc, nil
}

func scanScanRow(r rowScanner) (Scan, error) {
	var sc Scan
	var startedAt string
	var finishedAt sql.NullString
	err := r.Scan(&sc.ID, &sc.SourceName, &sc.Profile, &sc.Status,
		&startedAt, &finishedAt, &sc.StatsJSON, &sc.TableIdentityVersion,
		&sc.ConfigFingerprint, &sc.TaxonomyVersion, &sc.DetectorsVersion, &sc.BinaryVersion)
	if err != nil {
		return sc, err
	}
	sc.StartedAt, _ = time.Parse(time.RFC3339, startedAt)
	if finishedAt.Valid && finishedAt.String != "" {
		t, _ := time.Parse(time.RFC3339, finishedAt.String)
		sc.FinishedAt = &t
	}
	return sc, nil
}

// TableProgress — чекпоинт таблицы прогона (прогресс GET /api/v1/scans/{id}).
type TableProgress struct {
	Table    string `json:"table"`
	RowCount int64  `json:"row_count"`
	Status   string `json:"status"` // done | failed | skipped
	Error    string `json:"error,omitempty"`
}

// ScanTables возвращает чекпоинты таблиц прогона (blueprint п. 13).
func (s *Store) ScanTables(ctx context.Context, scanID string) ([]TableProgress, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT table_name, row_count, status, error
		FROM scan_tables WHERE scan_id = ? ORDER BY table_name`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TableProgress
	for rows.Next() {
		var tp TableProgress
		if err := rows.Scan(&tp.Table, &tp.RowCount, &tp.Status, &tp.Error); err != nil {
			return nil, err
		}
		out = append(out, tp)
	}
	return out, rows.Err()
}

// SetScanStatus помечает прогон терминальным статусом без stats_json
// (мягкая остановка через API, п. 11.2 stop: движок сам финализирует —
// метод нужен лишь как защита от «зависшего» running). Не трогает прогоны
// в терминальном статусе.
func (s *Store) SetScanStatus(ctx context.Context, id, status string, finishedAt time.Time) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE scans SET status = ?, finished_at = ? WHERE id = ? AND status = 'running'`,
		status, finishedAt.UTC().Format(time.RFC3339), id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("прогон %s не в статусе running", id)
	}
	return nil
}
