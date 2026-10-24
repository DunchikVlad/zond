// Package audit — security audit log (ADR-0013, blueprint п. 14.2): каноническая
// форма записи, цепочка хэшей и верификация. Хранение — таблица audit_log
// (миграция 0004, append-only: код + триггеры UPDATE/DELETE); все записи идут
// через единственное соединение store (SetMaxOpenConns(1)) — порядок цепочки
// обеспечен последовательным писателем, hash-chain считается в той же
// транзакции, что и INSERT.
//
// Каноническая форма (зафиксирована, изменения только с версией и миграцией —
// см. runbook audit-hash-chain-broken.md): UTF-8 JSON с сортированными ключами
// над полями {seq,ts,actor,category,action,target,details_json} + терминатор
// "\n"; entry_hash = sha256(prev_hash | canonical). Genesis prev_hash = "".
// encoding/json сериализует map с ключами в лексикографическом порядке —
// детерминизм гарантирован стандартной библиотекой.
package audit

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// Категории событий (blueprint п. 14.2). auth/authorization/review/config/
// secrets/admin введены инкрементами 5в–5г; alert — алертинг (S6в, п. 17).
const (
	CatAuth    = "auth"          // SSO-входы/неудачи, logout, SLO, admin-токен
	CatAuthz   = "authorization" // отказы 403
	CatReview  = "review"        // confirm/reject/relabel
	CatScan    = "scan"          // start/stop/resume/finish
	CatAgent   = "agent"         // каждый вызов LLM (со ссылкой на agent_calls)
	CatConfig  = "config"        // изменения sources/агентов/порогов
	CatExport  = "export"        // экспорт вердиктов и аудита
	CatSecrets = "secrets"       // факт резолва секрета (без значений)
	CatAdmin   = "admin"         // роли, API-токены
	CatAlert   = "alert"         // алертинг (п. 17): raise/resolve событий правил
)

// Event — аудит-событие до записи (без seq/hash — они назначаются при вставке).
type Event struct {
	Actor    string         // кто: sso:<subject> | token:<id> | cli (п. 14.2)
	Category string         // Cat*
	Action   string         // scan_start | scan_finish | agent_call | audit_export
	Target   string         // scan:<id> | agent:<id> | verdict:<id> | export
	Details  map[string]any // сводка; без сырых значений и секретов (ADR-0010)
	TS       time.Time      // момент события (UTC при сериализации)
}

// Entry — строка audit_log с цепочкой.
type Entry struct {
	Seq       int64
	TS        time.Time
	Actor     string
	Category  string
	Action    string
	Target    string
	Details   map[string]any
	PrevHash  string
	EntryHash string
}

// GenesisPrevHash — prev_hash первой записи цепочки (зафиксировано в ADR-impl-5а).
const GenesisPrevHash = ""

// canonical — каноническая сериализация записи (blueprint п. 14.2):
// UTF-8 JSON с сортированными ключами + терминатор "\n".
func canonical(seq int64, ts time.Time, actor, category, action, target, details string) string {
	m := map[string]any{
		"seq": seq, "ts": ts.UTC().Format(time.RFC3339), "actor": actor,
		"category": category, "action": action, "target": target,
		"details_json": details,
	}
	b, _ := json.Marshal(m) // map[string]any → ключи отсортированы stdlib
	return string(b) + "\n"
}

// entryHash — entry_hash = sha256(prev_hash | canonical) (п. 14.2).
func entryHash(prevHash, canonicalEntry string) string {
	sum := sha256.Sum256([]byte(prevHash + canonicalEntry))
	return hex.EncodeToString(sum[:])
}

// CanonicalEntry — каноническая сериализация записи (blueprint п. 14.2):
// UTF-8 JSON с сортированными ключами + терминатор "\n". Экспортирована для
// SIEM-sink (S8-3): на провод уходит именно она (фрейминг NDJSON для
// JSON-over-TCP; полезная нагрузка CEF для syslog) — внешняя сверка по
// hash-chain не зависит от внутреннего формата.
func CanonicalEntry(seq int64, ts time.Time, actor, category, action, target, details string) string {
	return canonical(seq, ts, actor, category, action, target, details)
}

// AppendTx пишет события в audit_log внутри уже открытой транзакции,
// продолжая цепочку от последней записи. Вызывается из store (единственный
// писатель) — атомарность с вердиктами/вызовами той же транзакции (п. 13/14.2).
// Пустой список — no-op. SIEM-sink (S8-3) читает журнал по закладке
// (audit_sink_state, миграция 0009) — записи не помечаются при вставке:
// очередь = сам журнал, потеря недопустима по построению.
func AppendTx(ctx context.Context, tx *sql.Tx, events []Event) error {
	if len(events) == 0 {
		return nil
	}
	var lastSeq sql.NullInt64
	var prevHash string
	row := tx.QueryRowContext(ctx,
		`SELECT seq, entry_hash FROM audit_log ORDER BY seq DESC LIMIT 1`)
	if err := row.Scan(&lastSeq, &prevHash); err != nil {
		if err == sql.ErrNoRows {
			prevHash = GenesisPrevHash
		} else {
			return fmt.Errorf("audit: чтение хвоста цепочки: %w", err)
		}
	}
	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO audit_log (seq, ts, actor, category, action, target, details_json, prev_hash, entry_hash)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	seq := lastSeq.Int64
	for i := range events {
		e := &events[i]
		details, err := json.Marshal(e.Details)
		if err != nil {
			return fmt.Errorf("audit: details события %s/%s: %w", e.Category, e.Action, err)
		}
		seq++
		hash := entryHash(prevHash, canonical(seq, e.TS, e.Actor, e.Category, e.Action, e.Target, string(details)))
		if _, err := stmt.ExecContext(ctx, seq, e.TS.UTC().Format(time.RFC3339),
			e.Actor, e.Category, e.Action, e.Target, string(details), prevHash, hash); err != nil {
			return fmt.Errorf("audit: вставка события %s/%s: %w", e.Category, e.Action, err)
		}
		prevHash = hash
	}
	return nil
}

// Report — результат верификации цепочки (zond audit verify, runbook
// audit-hash-chain-broken.md: первый проблемный seq и тип расхождения).
type Report struct {
	Checked  int64  // сколько записей проверено
	BrokenAt int64  // seq первой проблемной записи; 0 = цепочка цела
	Reason   string // человекочитаемая причина разрыва
}

// OK — целостность подтверждена.
func (r *Report) OK() bool { return r.BrokenAt == 0 }

// Verify пересчитывает цепочку по всем записям и находит первый разрыв:
// несовпадение prev_hash с хэшем предыдущей записи или пересчитанного entry_hash.
func Verify(ctx context.Context, db *sql.DB) (*Report, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT seq, ts, actor, category, action, target, details_json, prev_hash, entry_hash
		FROM audit_log ORDER BY seq`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	rep := &Report{}
	prevHash := GenesisPrevHash
	for rows.Next() {
		var seq int64
		var ts, actor, category, action, target, details, prev, hash string
		if err := rows.Scan(&seq, &ts, &actor, &category, &action, &target, &details, &prev, &hash); err != nil {
			return nil, err
		}
		rep.Checked++
		if prev != prevHash {
			rep.BrokenAt = seq
			rep.Reason = fmt.Sprintf("prev_hash не совпадает с entry_hash записи %d (ожидался %q, в записи %q)", seq-1, prevHash, prev)
			return rep, nil
		}
		tsT, _ := time.Parse(time.RFC3339, ts)
		want := entryHash(prev, canonical(seq, tsT, actor, category, action, target, details))
		if hash != want {
			rep.BrokenAt = seq
			rep.Reason = fmt.Sprintf("entry_hash не сходится с канонической формой (подмена полей записи %d?)", seq)
			return rep, nil
		}
		prevHash = hash
	}
	return rep, rows.Err()
}

// Filter — фильтры выборки для экспорта (п. 14.2: actor/тип/дата/scan_id).
type Filter struct {
	Actor    string
	Category string
	Since    *time.Time
	ScanID   string // target = 'scan:<id>' или target LIKE 'scan:<id>:%'
	Limit    int    // 0 — без лимита
}

// List возвращает записи аудита по фильтрам (для zond audit export и будущей
// страницы /audit; просмотр — только роль admin, п. 14.2).
func List(ctx context.Context, db *sql.DB, f Filter) ([]Entry, error) {
	q := `SELECT seq, ts, actor, category, action, target, details_json, prev_hash, entry_hash FROM audit_log`
	var where string
	var args []any
	if f.Actor != "" {
		where += " AND actor = ?"
		args = append(args, f.Actor)
	}
	if f.Category != "" {
		where += " AND category = ?"
		args = append(args, f.Category)
	}
	if f.Since != nil {
		where += " AND ts >= ?"
		args = append(args, f.Since.UTC().Format(time.RFC3339))
	}
	if f.ScanID != "" {
		// События скана (target scan:<id>) и связанные вызовы агентов
		// (scan_id в details, п. 14.2 — «по scan_id» для /audit).
		where += " AND (target = ? OR target LIKE ? OR details_json LIKE ?)"
		args = append(args, "scan:"+f.ScanID, "scan:"+f.ScanID+":%",
			"%\"scan_id\":\""+f.ScanID+"\"%")
	}
	if where != "" {
		q += " WHERE " + where[5:]
	}
	q += " ORDER BY seq"
	if f.Limit > 0 {
		q += " LIMIT ?"
		args = append(args, f.Limit)
	}
	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Entry
	for rows.Next() {
		var e Entry
		var ts, details string
		if err := rows.Scan(&e.Seq, &ts, &e.Actor, &e.Category, &e.Action, &e.Target, &details, &e.PrevHash, &e.EntryHash); err != nil {
			return nil, err
		}
		e.TS, _ = time.Parse(time.RFC3339, ts)
		e.Details = map[string]any{}
		if details != "" {
			if err := json.Unmarshal([]byte(details), &e.Details); err != nil {
				return nil, fmt.Errorf("audit: запись %d: details: %w", e.Seq, err)
			}
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// SinkEntry — событие аудита для доставки во внешний SIEM (S8-3, п. 14.2).
type SinkEntry struct {
	Seq       int64
	Canonical string // каноническая форма события (на провод — она, п. 14.2)
	EntryHash string
}

// SinkEntries — события журнала за закладкой sink (seq > afterSeq) в
// порядке цепочки. Очередь доставки = сам audit_log (потеря недопустима по
// построению); воркер двигает закладку только за доставленное (sink.go).
// Лимит обязателен (пакетная доставка; воркер крутит цикл).
func SinkEntries(ctx context.Context, db *sql.DB, afterSeq int64, limit int) ([]SinkEntry, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("audit: sink entries: лимит обязателен (>0)")
	}
	rows, err := db.QueryContext(ctx, `
		SELECT seq, ts, actor, category, action, target, details_json, entry_hash
		FROM audit_log WHERE seq > ? ORDER BY seq LIMIT ?`, afterSeq, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SinkEntry
	for rows.Next() {
		var e SinkEntry
		var ts, actor, category, action, target, details string
		if err := rows.Scan(&e.Seq, &ts, &actor, &category, &action, &target, &details, &e.EntryHash); err != nil {
			return nil, err
		}
		t, _ := time.Parse(time.RFC3339, ts)
		e.Canonical = canonical(e.Seq, t, actor, category, action, target, details)
		out = append(out, e)
	}
	return out, rows.Err()
}

// SinkLastSeq — закладка доставки SIEM-sink (миграция 0009): последний
// доставленный seq audit_log. Строка создаётся миграцией (0 = ничего не
// доставлено).
func SinkLastSeq(ctx context.Context, db *sql.DB) (int64, error) {
	var seq int64
	err := db.QueryRowContext(ctx,
		`SELECT last_seq FROM audit_sink_state WHERE id = 1`).Scan(&seq)
	return seq, err
}

// SinkAdvance — продвинуть закладку за доставленное событие (п. 14.2:
// закладка двигается только вперёд и только за подтверждённую доставку).
// errText — диагностика последней неудачи (обрезана до 256), пусто при ok.
func SinkAdvance(ctx context.Context, db *sql.DB, lastSeq int64, errText string, now time.Time) error {
	if len(errText) > 256 {
		errText = errText[:256]
	}
	_, err := db.ExecContext(ctx,
		`UPDATE audit_sink_state SET last_seq = ?, last_error = ?, updated_at = ? WHERE id = 1`,
		lastSeq, errText, now.UTC().Format(time.RFC3339))
	return err
}

// SinkPending — размер недоставленного хвоста журнала (doctor/метрики п. 17):
// события audit_log за закладкой sink.
func SinkPending(ctx context.Context, db *sql.DB) (int, error) {
	last, err := SinkLastSeq(ctx, db)
	if err != nil {
		return 0, err
	}
	var n int
	err = db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM audit_log WHERE seq > ?`, last).Scan(&n)
	return n, err
}
