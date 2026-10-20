// Retention сканов (blueprint п. 15.4): автоочистка прогонов старше срока
// хранения вместе со связанными данными; факт очистки аудируется вызывающей
// задачей шедулера (actor "scheduler", п. 14.2).
package store

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// PurgeScansOlderThan удаляет прогоны, завершённые раньше cutoff, вместе со
// связанными scan_tables, verdicts, agent_calls и review_events — одной
// транзакцией (blueprint п. 15.4: сканы + вердикты + agent_calls хранятся
// одинаковый срок; FK п. 11.1 требуют порядок удаления «дети → родители»:
// agent_calls/review_events → verdicts → scan_tables → scans). Возвращает
// число удалённых прогонов. Прогоны без finished_at (running) не трогаются.
func (s *Store) PurgeScansOlderThan(ctx context.Context, cutoff time.Time) (int, error) {
	cut := cutoff.UTC().Format(time.RFC3339)
	ids, err := s.scanIDsFinishedBefore(ctx, cut)
	if err != nil {
		return 0, err
	}
	if len(ids) == 0 {
		return 0, nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	ph := placeholders(len(ids))
	args := make([]any, len(ids))
	for i, id := range ids {
		args[i] = id
	}
	// agent_calls ссылается на scans(id) и verdicts(id) — удаляем первым,
	// включая записи по вердиктам прогонов (не только по scan_id, п. 10.6).
	steps := []string{
		`DELETE FROM agent_calls WHERE verdict_id IN (SELECT id FROM verdicts WHERE scan_id IN (` + ph + `))`,
		`DELETE FROM agent_calls WHERE scan_id IN (` + ph + `)`,
		`DELETE FROM review_events WHERE verdict_id IN (SELECT id FROM verdicts WHERE scan_id IN (` + ph + `))`,
		`DELETE FROM verdicts WHERE scan_id IN (` + ph + `)`,
		`DELETE FROM scan_tables WHERE scan_id IN (` + ph + `)`,
		`DELETE FROM scans WHERE id IN (` + ph + `)`,
	}
	for _, q := range steps {
		if _, err := tx.ExecContext(ctx, q, args...); err != nil {
			return 0, fmt.Errorf("retention: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return len(ids), nil
}

// scanIDsFinishedBefore — id прогонов с finished_at старше cut. RFC3339 в UTC
// сортируется лексикографически хронологически — сравнение строк корректно.
func (s *Store) scanIDsFinishedBefore(ctx context.Context, cut string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id FROM scans WHERE finished_at != '' AND finished_at < ?`, cut)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// placeholders — "?,?,…" для n параметров (database/sql не разворачивает
// срезы для драйвера sqlite).
func placeholders(n int) string {
	return strings.TrimSuffix(strings.Repeat("?,", n), ",")
}
