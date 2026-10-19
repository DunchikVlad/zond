package store

import (
	"context"
	"testing"

	"github.com/DunchikVlad/zond/internal/audit"
	"github.com/DunchikVlad/zond/internal/verdict"
)

// Append-only audit_log (миграция 0004, blueprint п. 14.2): UPDATE/DELETE
// запрещены триггерами даже при прямом доступе к БД (защита в глубину).
func TestAuditLogAppendOnlyTriggers(t *testing.T) {
	st := openTest(t)
	ctx := context.Background()
	if err := st.AppendAudit(ctx, []audit.Event{{
		Actor: "cli", Category: audit.CatScan, Action: "scan_start", Target: "scan:s1",
	}}); err != nil {
		t.Fatalf("AppendAudit: %v", err)
	}
	var seq int64
	if err := st.db.QueryRow(`SELECT seq FROM audit_log`).Scan(&seq); err != nil {
		t.Fatalf("query: %v", err)
	}
	if _, err := st.db.Exec(`UPDATE audit_log SET action = 'forged' WHERE seq = ?`, seq); err == nil {
		t.Fatal("UPDATE audit_log должен быть запрещён триггером")
	}
	if _, err := st.db.Exec(`DELETE FROM audit_log WHERE seq = ?`, seq); err == nil {
		t.Fatal("DELETE audit_log должен быть запрещён триггером")
	}
	// после попыток подмены цепочка цела и событие на месте
	rep, err := st.AuditVerify(ctx)
	if err != nil || !rep.OK() || rep.Checked != 1 {
		t.Fatalf("цепочка после попыток подмены: %+v, %v", rep, err)
	}
}

// AppendAudit продолжает цепочку: две пачки событий сходятся последовательно.
func TestAppendAuditChainAcrossCalls(t *testing.T) {
	st := openTest(t)
	ctx := context.Background()
	mk := func(action string) audit.Event {
		return audit.Event{Actor: "cli", Category: audit.CatScan, Action: action, Target: "scan:s1"}
	}
	if err := st.AppendAudit(ctx, []audit.Event{mk("scan_start")}); err != nil {
		t.Fatalf("пачка 1: %v", err)
	}
	if err := st.AppendAudit(ctx, []audit.Event{mk("scan_finish")}); err != nil {
		t.Fatalf("пачка 2: %v", err)
	}
	entries, err := st.AuditList(ctx, audit.Filter{ScanID: "s1"})
	if err != nil || len(entries) != 2 {
		t.Fatalf("ожидалось 2 записи: %+v, %v", entries, err)
	}
	if entries[0].PrevHash != audit.GenesisPrevHash || entries[1].PrevHash != entries[0].EntryHash {
		t.Fatalf("связь цепочки нарушена: %+v", entries)
	}
	rep, err := st.AuditVerify(ctx)
	if err != nil || !rep.OK() {
		t.Fatalf("verify: %+v, %v", rep, err)
	}
}

// Аудит-события коммитятся атомарно с вердиктами и вызовами (п. 13/14.2):
// FK-провал вызова откатывает и события.
func TestSaveVerdictsWithCallsRollsBackEvents(t *testing.T) {
	st := openTest(t)
	ctx := context.Background()
	mustSaveScan(t, st, "s1")
	v := testVerdict("v1", "s1")
	call := testCall("c1", "s1", "ghost-verdict") // FK: вердикта нет
	events := []audit.Event{{Actor: "cli", Category: audit.CatAgent, Action: "agent_call", Target: "agent:zond-main"}}
	if err := st.SaveVerdictsWithCalls(ctx, []verdict.Verdict{v}, []AgentCall{call}, events); err == nil {
		t.Fatal("ожидался FK-отказ (ghost verdict_id)")
	}
	n := 0
	if err := st.db.QueryRow(`SELECT COUNT(*) FROM audit_log`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("события попали в аудит несмотря на откат: n=%d, %v", n, err)
	}
}
