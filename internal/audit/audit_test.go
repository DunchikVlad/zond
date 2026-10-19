package audit

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// Тесты аудит-канала (ADR-0013, blueprint п. 14.2): каноническая форма,
// hash-chain, append-only триггеры, верификация, фильтры выборки.

// openTestDB открывает SQLite через store-миграции не нужен: достаточно
// схемы audit_log — создаём напрямую (пакет audit не зависит от store).
func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	_, err = db.Exec(`CREATE TABLE audit_log (
		seq INTEGER PRIMARY KEY AUTOINCREMENT,
		ts TEXT NOT NULL, actor TEXT NOT NULL, category TEXT NOT NULL,
		action TEXT NOT NULL, target TEXT NOT NULL DEFAULT '',
		details_json TEXT NOT NULL DEFAULT '{}',
		prev_hash TEXT NOT NULL, entry_hash TEXT NOT NULL)`)
	if err != nil {
		t.Fatalf("schema: %v", err)
	}
	return db
}

// append через транзакцию — как в проде (store.AppendAudit / AppendTx).
func appendTx(t *testing.T, db *sql.DB, events ...Event) {
	t.Helper()
	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := AppendTx(context.Background(), tx, events); err != nil {
		t.Fatalf("AppendTx: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
}

func TestAppendAndVerifyChain(t *testing.T) {
	db := openTestDB(t)
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	appendTx(t, db,
		Event{Actor: "cli", Category: CatScan, Action: "scan_start", Target: "scan:s1", Details: map[string]any{"source": "ch"}, TS: now},
		Event{Actor: "cli", Category: CatAgent, Action: "agent_call", Target: "agent:zond-main", Details: map[string]any{"call_id": "c1", "status": "ok"}, TS: now.Add(time.Second)},
		Event{Actor: "cli", Category: CatScan, Action: "scan_finish", Target: "scan:s1", Details: map[string]any{"status": "done"}, TS: now.Add(2 * time.Second)},
	)
	rep, err := Verify(context.Background(), db)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !rep.OK() || rep.Checked != 3 {
		t.Fatalf("цепочка из 3 записей должна сходиться: %+v", rep)
	}
}

// TestCanonicalDeterministic — одинаковое событие в двух независимых
// журналах даёт одинаковый entry_hash (ключи map сериализуются stdlib
// в сортированном порядке — каноническая форма не зависит от порядка
// вставки ключей и итерации по map).
func TestCanonicalDeterministic(t *testing.T) {
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	mkDetails := func() map[string]any {
		d := map[string]any{}
		d["zeta"] = 1 // порядок вставки намеренно «обратный»
		d["alpha"] = 2
		d["mid"] = 3
		return d
	}
	hashOfFirst := func() string {
		db := openTestDB(t)
		appendTx(t, db, Event{Actor: "cli", Category: CatScan, Action: "scan_start",
			Target: "scan:s1", Details: mkDetails(), TS: now})
		var h string
		if err := db.QueryRow(`SELECT entry_hash FROM audit_log WHERE seq = 1`).Scan(&h); err != nil {
			t.Fatalf("query: %v", err)
		}
		return h
	}
	h1, h2 := hashOfFirst(), hashOfFirst()
	if h1 != h2 {
		t.Fatalf("каноническая форма недетерминирована: %s vs %s", h1, h2)
	}
}

// TestVerifyDetectsBrokenChain — подмена entry_hash (запись вставлена мимо
// кода; в тестовой схеме триггеров нет — в проде мешает ещё и миграция 0004)
// обнаруживается верификацией с указанием проблемного seq.
func TestVerifyDetectsBrokenChain(t *testing.T) {
	db := openTestDB(t)
	now := time.Now().UTC()
	appendTx(t, db,
		Event{Actor: "cli", Category: CatScan, Action: "scan_start", Target: "scan:s1", TS: now},
		Event{Actor: "cli", Category: CatScan, Action: "scan_finish", Target: "scan:s1", TS: now},
	)
	if _, err := db.Exec(`UPDATE audit_log SET entry_hash = 'f' || substr(entry_hash, 2) WHERE seq = 1`); err != nil {
		t.Fatalf("подмена entry_hash: %v", err)
	}
	rep, err := Verify(context.Background(), db)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if rep.OK() || rep.BrokenAt != 1 {
		t.Fatalf("подмена entry_hash записи 1 не обнаружена: %+v", rep)
	}
}

// TestVerifyDetectsWrongPrevHash — разрыв связи prev_hash → entry_hash.
func TestVerifyDetectsWrongPrevHash(t *testing.T) {
	db := openTestDB(t)
	now := time.Now().UTC()
	appendTx(t, db,
		Event{Actor: "cli", Category: CatScan, Action: "scan_start", Target: "scan:s1", TS: now},
		Event{Actor: "cli", Category: CatScan, Action: "scan_finish", Target: "scan:s1", TS: now},
	)
	if _, err := db.Exec(`UPDATE audit_log SET prev_hash = 'forged' WHERE seq = 2`); err != nil {
		t.Fatalf("UPDATE: %v", err)
	}
	rep, err := Verify(context.Background(), db)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if rep.OK() || rep.BrokenAt != 2 {
		t.Fatalf("неверный prev_hash записи 2 не обнаружен: %+v", rep)
	}
}

// TestGenesisPrevHash — первая запись ссылается на фиксированный genesis ("").
func TestGenesisPrevHash(t *testing.T) {
	db := openTestDB(t)
	appendTx(t, db, Event{Actor: "cli", Category: CatScan, Action: "scan_start", Target: "scan:s1", TS: time.Now().UTC()})
	var prev string
	if err := db.QueryRow(`SELECT prev_hash FROM audit_log WHERE seq = 1`).Scan(&prev); err != nil {
		t.Fatalf("query: %v", err)
	}
	if prev != GenesisPrevHash {
		t.Fatalf("prev_hash первой записи %q, ожидался genesis %q", prev, GenesisPrevHash)
	}
}

// TestListFilters — фильтры actor/category/since/scan и порядок по seq.
func TestListFilters(t *testing.T) {
	db := openTestDB(t)
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	appendTx(t, db,
		Event{Actor: "cli", Category: CatScan, Action: "scan_start", Target: "scan:s1", TS: now},
		Event{Actor: "cli", Category: CatAgent, Action: "agent_call", Target: "agent:zond-main", TS: now.Add(time.Second)},
		Event{Actor: "token:x", Category: CatScan, Action: "scan_start", Target: "scan:s2", TS: now.Add(2 * time.Second)},
	)
	ctx := context.Background()
	all, err := List(ctx, db, Filter{})
	if err != nil || len(all) != 3 {
		t.Fatalf("List все: %d, %v", len(all), err)
	}
	byActor, err := List(ctx, db, Filter{Actor: "token:x"})
	if err != nil || len(byActor) != 1 || byActor[0].Target != "scan:s2" {
		t.Fatalf("фильтр actor: %+v, %v", byActor, err)
	}
	byScan, err := List(ctx, db, Filter{ScanID: "s1"})
	if err != nil || len(byScan) != 1 || byScan[0].Action != "scan_start" {
		t.Fatalf("фильтр scan: %+v, %v", byScan, err)
	}
	since := now.Add(time.Second)
	bySince, err := List(ctx, db, Filter{Since: &since})
	if err != nil || len(bySince) != 2 {
		t.Fatalf("фильтр since: %+v, %v", bySince, err)
	}
	byCat, err := List(ctx, db, Filter{Category: CatAgent})
	if err != nil || len(byCat) != 1 || byCat[0].Action != "agent_call" {
		t.Fatalf("фильтр category: %+v, %v", byCat, err)
	}
}

// TestAppendEmpty — пустой список событий не трогает цепочку.
func TestAppendEmpty(t *testing.T) {
	db := openTestDB(t)
	if err := AppendTx(context.Background(), mustTx(t, db), nil); err != nil {
		t.Fatalf("AppendTx(nil): %v", err)
	}
	rep, err := Verify(context.Background(), db)
	if err != nil || rep.Checked != 0 || !rep.OK() {
		t.Fatalf("пустая цепочка: %+v, %v", rep, err)
	}
}

func mustTx(t *testing.T, db *sql.DB) *sql.Tx {
	t.Helper()
	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	t.Cleanup(func() { _ = tx.Rollback() })
	return tx
}
