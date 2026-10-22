// Журнал алертов встроенного алертинга (blueprint п. 17; миграция 0007):
// подъём/продление/закрытие по правилам (rule, target). Дедуп открытых —
// повторное срабатывание того же правила по той же цели продлевает
// last_seen_at вместо новой строки.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// Alert — запись журнала алертов.
type Alert struct {
	ID        int64
	Rule      string
	Severity  string // warning | critical
	Target    string // source:<name> | agent:<id> | audit_log
	Message   string
	Details   map[string]any
	State     string // open | resolved
	CreatedAt time.Time
	LastSeen  time.Time
	Resolved  *time.Time
}

// AlertRaise поднимает алерт: если открытого (rule, target) нет — вставка
// (created=true); иначе продление last_seen_at/details. Детерминированная
// дедупликация без гонок — единое соединение store (п. 13).
func (s *Store) AlertRaise(ctx context.Context, rule, severity, target, message string, details map[string]any, now time.Time) (bool, error) {
	if details == nil {
		details = map[string]any{}
	}
	dj, err := json.Marshal(details)
	if err != nil {
		return false, fmt.Errorf("alerts: details: %w", err)
	}
	nowStr := now.UTC().Format(time.RFC3339)
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO alerts (rule, severity, target, message, details_json, state, created_at, last_seen_at)
		SELECT ?, ?, ?, ?, ?, 'open', ?, ?
		WHERE NOT EXISTS (
			SELECT 1 FROM alerts WHERE rule = ? AND target = ? AND state = 'open'
		)`, rule, severity, target, message, string(dj), nowStr, nowStr, rule, target)
	if err != nil {
		return false, err
	}
	if n, _ := res.RowsAffected(); n > 0 {
		return true, nil
	}
	// Открытый алерт уже есть — продлеваем наблюдение.
	_, err = s.db.ExecContext(ctx, `
		UPDATE alerts SET last_seen_at = ?, details_json = ?, message = ?
		WHERE rule = ? AND target = ? AND state = 'open'`,
		nowStr, string(dj), message, rule, target)
	return false, err
}

// AlertResolveNotIn закрывает открытые алерты правил rules, чьи (rule,target)
// отсутствуют в active (правило перестало стрелять). Возвращает закрытые
// записи (для аудита и webhook).
func (s *Store) AlertResolveNotIn(ctx context.Context, rules []string, active map[string]bool, now time.Time) ([]Alert, error) {
	if len(rules) == 0 {
		return nil, nil
	}
	ph := placeholders(len(rules))
	args := make([]any, 0, len(rules))
	for _, r := range rules {
		args = append(args, r)
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, rule, severity, target, message, details_json FROM alerts
		 WHERE state = 'open' AND rule IN (`+ph+`)`, args...)
	if err != nil {
		return nil, err
	}
	var toResolve []Alert
	for rows.Next() {
		var a Alert
		var dj string
		if err := rows.Scan(&a.ID, &a.Rule, &a.Severity, &a.Target, &a.Message, &dj); err != nil {
			rows.Close()
			return nil, err
		}
		if !active[a.Rule+":"+a.Target] {
			_ = json.Unmarshal([]byte(dj), &a.Details)
			toResolve = append(toResolve, a)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	nowStr := now.UTC().Format(time.RFC3339)
	for _, a := range toResolve {
		if _, err := s.db.ExecContext(ctx,
			`UPDATE alerts SET state = 'resolved', resolved_at = ? WHERE id = ?`, nowStr, a.ID); err != nil {
			return nil, err
		}
	}
	return toResolve, nil
}

// AlertList — алерты по состоянию ("" — все), свежие первыми.
func (s *Store) AlertList(ctx context.Context, state string, limit int) ([]Alert, error) {
	q := `SELECT id, rule, severity, target, message, details_json, state, created_at, last_seen_at, resolved_at
		FROM alerts`
	var where string
	var args []any
	if state != "" {
		where = " WHERE state = ?"
		args = append(args, state)
	}
	q += where + ` ORDER BY id DESC`
	if limit > 0 {
		q += ` LIMIT ?`
		args = append(args, limit)
	}
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Alert
	for rows.Next() {
		var a Alert
		var dj, created, seen, resolved string
		if err := rows.Scan(&a.ID, &a.Rule, &a.Severity, &a.Target, &a.Message,
			&dj, &a.State, &created, &seen, &resolved); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(dj), &a.Details)
		a.CreatedAt, _ = time.Parse(time.RFC3339, created)
		a.LastSeen, _ = time.Parse(time.RFC3339, seen)
		if resolved != "" {
			if t, err := time.Parse(time.RFC3339, resolved); err == nil {
				a.Resolved = &t
			}
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// AlertOpenCount — число открытых алертов (бейдж навигации UI).
func (s *Store) AlertOpenCount(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM alerts WHERE state = 'open'`).Scan(&n)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	return n, err
}
