package scanengine

import (
	"testing"

	"github.com/DunchikVlad/zond/internal/audit"
)

// E2E инкремента 5а (ADR-0013, blueprint п. 14.2): скан пишет аудит —
// scan_start, scan_finish и событие agent_call на каждый вызов LLM (1:1 с
// agent_calls), цепочка хэшей сходится, фильтры выборки работают.

func TestScanWritesAuditEvents(t *testing.T) {
	eng, st := testEngine(t)
	cfg := eng.cfg
	cfg.Clustering = false
	eng = New(st, eng.meta, cfg)
	llm := llmWithVerify() // classify ok + verify ok на каждую серую колонку
	eng.SetLLM(llm, LLMIdentity{AgentID: testLLMID, Model: testLLMModel})

	rep, _ := scanAndList(t, eng, st, budgetSource()) // 2 колонки → 2 classify + 2 verify

	entries, err := st.AuditList(t.Context(), audit.Filter{ScanID: rep.ScanID})
	if err != nil {
		t.Fatalf("AuditList: %v", err)
	}
	// scan_start + scan_finish + 4 agent_call (по одному на каждый вызов)
	if len(entries) != 6 {
		t.Fatalf("записей аудита %d, ожидалось 6 (start+finish+4 вызова): %+v", len(entries), entries)
	}
	var start, finish, calls int
	for _, e := range entries {
		if e.Actor != "cli" {
			t.Fatalf("actor события %q, ожидался cli: %+v", e.Actor, e)
		}
		switch e.Action {
		case "scan_start":
			start++
			if e.Category != audit.CatScan || e.Details["source"] != "fake" {
				t.Fatalf("scan_start искажён: %+v", e)
			}
		case "scan_finish":
			finish++
			if e.Details["status"] != "done" || e.Details["verdicts"] == nil {
				t.Fatalf("scan_finish искажён: %+v", e)
			}
		case "agent_call":
			calls++
			if e.Category != audit.CatAgent || e.Target != "agent:"+testLLMID {
				t.Fatalf("agent_call искажён: %+v", e)
			}
			for _, k := range []string{"call_id", "verdict_id", "model", "status", "tokens_in", "cost_usd"} {
				if e.Details[k] == nil {
					t.Fatalf("в событии вызова нет %s: %+v", k, e)
				}
			}
		default:
			t.Fatalf("неожиданное событие: %+v", e)
		}
	}
	if start != 1 || finish != 1 || calls != 4 {
		t.Fatalf("start=%d finish=%d calls=%d, ожидалось 1/1/4", start, finish, calls)
	}
	ver, err := st.AuditVerify(t.Context())
	if err != nil || !ver.OK() {
		t.Fatalf("hash-chain после скана: %+v, %v", ver, err)
	}
}

// Скан без LLM тоже аудируется (start/finish) — слои 0–1 по умолчанию.
func TestScanWithoutLLMAudited(t *testing.T) {
	eng, st := testEngine(t)
	rep, _ := scanAndList(t, eng, st, testSource())
	entries, err := st.AuditList(t.Context(), audit.Filter{ScanID: rep.ScanID})
	if err != nil || len(entries) != 2 {
		t.Fatalf("ожидалось start+finish: %+v, %v", entries, err)
	}
	if entries[0].Action != "scan_start" || entries[1].Action != "scan_finish" {
		t.Fatalf("порядок событий нарушен: %+v", entries)
	}
}
