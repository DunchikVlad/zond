// Фильтрованные выборки вердиктов и ручное ревью для REST API
// (blueprint п. 11.2): GET /verdicts с сортировкой risk_first,
// POST /verdicts/{id}/review — атомарная смена review_status + review_events
// + аудит (п. 13/14.2, fail-closed).
package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/DunchikVlad/zond/internal/audit"
	"github.com/DunchikVlad/zond/internal/verdict"
)

// VerdictFilter — фильтры списка вердиктов (GET /api/v1/verdicts).
type VerdictFilter struct {
	ScanID       string
	Label        string
	Sensitivity  string  // PII|PCI|PHI|none
	MinConf      float64 // 0 — без порога
	ReviewStatus string
	Table        string // подстрока имени таблицы (поиск UI)
	ClusterID    string
	LLMStatus    string // S9-2: not_called|called|cache_hit|small_sample|cluster_propagated|budget_exceeded|error
	RiskFirst    bool   // сортировка «риск первыми»: PCI/PII × confidence desc
	Limit        int
	Offset       int
}

// ListVerdictsFiltered возвращает вердикты по фильтру и общее число строк
// под фильтром (пагинация UI, п. 11.2).
func (s *Store) ListVerdictsFiltered(ctx context.Context, f VerdictFilter) ([]verdict.Verdict, int, error) {
	limit, offset := normalizePage(f.Limit, f.Offset, 50)
	var cond []string
	var args []any
	if f.ScanID != "" {
		cond = append(cond, "scan_id = ?")
		args = append(args, f.ScanID)
	}
	if f.Label != "" {
		cond = append(cond, "label = ?")
		args = append(args, f.Label)
	}
	if f.Sensitivity != "" {
		cond = append(cond, "sensitivity = ?")
		args = append(args, f.Sensitivity)
	}
	if f.MinConf > 0 {
		cond = append(cond, "confidence >= ?")
		args = append(args, f.MinConf)
	}
	if f.ReviewStatus != "" {
		cond = append(cond, "review_status = ?")
		args = append(args, f.ReviewStatus)
	}
	if f.Table != "" {
		cond = append(cond, "table_name LIKE ?")
		args = append(args, "%"+f.Table+"%")
	}
	if f.ClusterID != "" {
		cond = append(cond, "cluster_id = ?")
		args = append(args, f.ClusterID)
	}
	if f.LLMStatus != "" {
		cond = append(cond, "llm_status = ?")
		args = append(args, f.LLMStatus)
	}
	where := ""
	if len(cond) > 0 {
		where = " WHERE " + strings.Join(cond, " AND ")
	}
	var total int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM verdicts`+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	// risk_first (п. 11.2): чувствительные классы выше, внутри — по убыванию
	// уверенности; дефолт — стабильный порядок этапа 1 (table, path).
	order := " ORDER BY table_name, path"
	if f.RiskFirst {
		order = ` ORDER BY CASE sensitivity WHEN 'PCI' THEN 0 WHEN 'PII' THEN 1 WHEN 'PHI' THEN 2 ELSE 3 END,
		          confidence DESC, table_name, path`
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, scan_id, table_name, path, native_type, label, sensitivity, confidence,
		       evidence_layer, evidence, taxonomy_version, detectors_version, prompt_version,
		       sample_size, cluster_id, llm_status, review_status, final_label, reviewed_by, reviewed_at, created_at
		FROM verdicts`+where+order+` LIMIT ? OFFSET ?`, append(args, limit, offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []verdict.Verdict
	for rows.Next() {
		v, err := scanVerdict(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, v)
	}
	return out, total, rows.Err()
}

// GetVerdict возвращает вердикт по id; sql.ErrNoRows, если не найден.
func (s *Store) GetVerdict(ctx context.Context, id string) (*verdict.Verdict, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, scan_id, table_name, path, native_type, label, sensitivity, confidence,
		       evidence_layer, evidence, taxonomy_version, detectors_version, prompt_version,
		       sample_size, cluster_id, llm_status, review_status, final_label, reviewed_by, reviewed_at, created_at
		FROM verdicts WHERE id = ?`, id)
	v, err := scanVerdict(row)
	if err != nil {
		return nil, err
	}
	return &v, nil
}

// ReviewAction — действие ручного ревью (POST /api/v1/verdicts/{id}/review).
type ReviewAction string

const (
	ReviewConfirm ReviewAction = "confirm"
	ReviewReject  ReviewAction = "reject"
	ReviewRelabel ReviewAction = "relabel"
)

// reviewResultStatus — маппинг действия на review_status вердикта (п. 5.4).
func reviewResultStatus(a ReviewAction) verdict.ReviewStatus {
	switch a {
	case ReviewConfirm:
		return verdict.StatusConfirmed
	case ReviewReject:
		return verdict.StatusRejected
	default:
		return verdict.StatusRelabelled
	}
}

// ReviewConflict — ошибка-конфликт ревью (п. 11.2 код review_conflict):
// действие бессмысленно для текущего состояния (повторное действие, relabel
// на тот же лейбл, relabel без лейбла).
type ReviewConflict struct{ Reason string }

func (e *ReviewConflict) Error() string { return e.Reason }

// ReviewEvent — строка append-only журнала ревью (п. 11.1).
type ReviewEvent struct {
	ID        string    `json:"id"`
	VerdictID string    `json:"verdict_id"`
	Action    string    `json:"action"`
	FromLabel string    `json:"from_label"`
	ToLabel   string    `json:"to_label"`
	Actor     string    `json:"actor"`
	TS        time.Time `json:"ts"`
}

// ApplyReview применяет действие ревью к вердикту АТОМАРНО: обновление
// review_status/final_label/reviewed_*, запись review_events и аудит-события —
// одной транзакцией (п. 13/14.2: действие без аудита не совершено).
// relabel требует newLabel из таксономии; actor — sso:<subject>/token:<id>/api
// (п. 14.2; SSO — инкремент 5в).
func (s *Store) ApplyReview(ctx context.Context, verdictID string, action ReviewAction, newLabel verdict.Label, actor string, now time.Time) (*verdict.Verdict, error) {
	if action != ReviewConfirm && action != ReviewReject && action != ReviewRelabel {
		return nil, &ReviewConflict{Reason: fmt.Sprintf("неизвестное действие %q", action)}
	}
	if action == ReviewRelabel && newLabel == "" {
		return nil, &ReviewConflict{Reason: "relabel требует label"}
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	row := tx.QueryRowContext(ctx, `
		SELECT id, scan_id, table_name, path, native_type, label, sensitivity, confidence,
		       evidence_layer, evidence, taxonomy_version, detectors_version, prompt_version,
		       sample_size, cluster_id, llm_status, review_status, final_label, reviewed_by, reviewed_at, created_at
		FROM verdicts WHERE id = ?`, verdictID)
	v, err := scanVerdict(row)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, err
		}
		return nil, fmt.Errorf("чтение вердикта: %w", err)
	}

	fromLabel := v.Label
	if v.FinalLabel != "" { // после предыдущего relabel «текущий» лейбл — final
		fromLabel = v.FinalLabel
	}
	toLabel := string(fromLabel)
	if action == ReviewRelabel {
		toLabel = string(newLabel)
		if newLabel == fromLabel {
			return nil, &ReviewConflict{Reason: "relabel на тот же лейбл"}
		}
	}
	status := reviewResultStatus(action)
	if v.ReviewStatus == status && action != ReviewRelabel {
		return nil, &ReviewConflict{Reason: fmt.Sprintf("вердикт уже в статусе %s", status)}
	}

	finalLabel := string(v.FinalLabel)
	switch action {
	case ReviewRelabel:
		finalLabel = string(newLabel)
	case ReviewReject:
		finalLabel = "" // отклонение снимает ручной лейбл
	}
	res, err := tx.ExecContext(ctx, `
		UPDATE verdicts
		SET review_status = ?, final_label = ?, reviewed_by = ?, reviewed_at = ?
		WHERE id = ?`,
		string(status), finalLabel, actor, now.UTC().Format(time.RFC3339), verdictID)
	if err != nil {
		return nil, err
	}
	if err := requireAffected(res, verdictID); err != nil {
		return nil, err
	}

	var evID [16]byte
	_, _ = rand.Read(evID[:])
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO review_events (id, verdict_id, action, from_label, to_label, actor, ts)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		hex.EncodeToString(evID[:]), verdictID, string(action),
		string(fromLabel), toLabel, actor, now.UTC().Format(time.RFC3339)); err != nil {
		return nil, fmt.Errorf("review_event: %w", err)
	}

	if err := audit.AppendTx(ctx, tx, []audit.Event{{
		Actor: actor, Category: audit.CatReview, Action: string(action),
		Target: "verdict:" + verdictID, TS: now,
		Details: map[string]any{
			"scan_id": v.ScanID, "table": v.Table, "path": v.Path,
			"from_label": string(fromLabel), "to_label": toLabel,
		},
	}}); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}

	v.ReviewStatus = status
	v.FinalLabel = verdict.Label(finalLabel)
	v.ReviewedBy = actor
	v.ReviewedAt = now.UTC()
	return &v, nil
}

// ListReviewEvents возвращает журнал ревью вердикта (детали GET /verdicts/{id}).
func (s *Store) ListReviewEvents(ctx context.Context, verdictID string) ([]ReviewEvent, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, verdict_id, action, from_label, to_label, actor, ts
		FROM review_events WHERE verdict_id = ? ORDER BY ts, id`, verdictID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ReviewEvent
	for rows.Next() {
		var e ReviewEvent
		var ts string
		if err := rows.Scan(&e.ID, &e.VerdictID, &e.Action, &e.FromLabel, &e.ToLabel, &e.Actor, &ts); err != nil {
			return nil, err
		}
		e.TS, _ = time.Parse(time.RFC3339, ts)
		out = append(out, e)
	}
	return out, rows.Err()
}

// VerdictsForExport — выгрузка вердиктов прогона для экспорта (п. 11.2):
// все строки без пагинации, но не более maxRows (export_max_rows, default
// 50 000; превышение — отказ 409 с предложением async, задел п. 11.2).
func (s *Store) VerdictsForExport(ctx context.Context, scanID string, maxRows int) ([]verdict.Verdict, int, error) {
	var total int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM verdicts WHERE scan_id = ?`, scanID).Scan(&total); err != nil {
		return nil, 0, err
	}
	if total > maxRows {
		return nil, total, nil
	}
	vs, err := s.ListVerdicts(ctx, scanID)
	if err != nil {
		return nil, 0, err
	}
	return vs, total, nil
}
