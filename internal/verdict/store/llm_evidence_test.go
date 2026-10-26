// Тесты S9-2 store-слоя: round-trip новых полей agent_calls/verdicts,
// фильтр llm_status, миграция 0011 (up/down/up и бэкфилл со схемы 0010).
package store

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/DunchikVlad/zond/internal/verdict"
	"github.com/pressly/goose/v3"
)

// TestAgentCallS92FieldsRoundTrip — S9-2: operation/answer-поля вызова и
// llm_status вердикта сохраняются и читаются через все выборки.
func TestAgentCallS92FieldsRoundTrip(t *testing.T) {
	st := openTest(t)
	ctx := context.Background()
	mustSaveScan(t, st, "s1")
	v := testVerdict("v1", "s1")
	v.LLMStatus = verdict.LLMStatusCalled
	call := testCall("c1", "s1", "v1")
	call.Operation = CallOpClassify
	call.AnswerLabel = "PHONE"
	call.AnswerConfidence = 0.95
	call.AnswerSensitivity = "PII"
	call.ReasonRU = "номера мобильных"
	call.Error = ""
	if err := st.SaveVerdictsWithCalls(ctx, []verdict.Verdict{v}, []AgentCall{call}, nil); err != nil {
		t.Fatalf("SaveVerdictsWithCalls: %v", err)
	}
	call2 := testCall("c2", "s1", "v1")
	call2.Operation = CallOpVerify
	call2.Status = "error"
	call2.AnswerLabel = ""
	call2.Error = "agentproxy: HTTP 500: boom"
	if err := st.SaveVerdictsWithCalls(ctx, nil, []AgentCall{call2}, nil); err != nil {
		t.Fatalf("вторая запись: %v", err)
	}

	got, err := st.GetVerdict(ctx, "v1")
	if err != nil {
		t.Fatalf("GetVerdict: %v", err)
	}
	if got.LLMStatus != verdict.LLMStatusCalled {
		t.Fatalf("llm_status не сохранился: %+v", got)
	}
	calls, err := st.ListAgentCalls(ctx, "s1")
	if err != nil || len(calls) != 2 {
		t.Fatalf("ListAgentCalls: %v, %+v", err, calls)
	}
	byID := map[string]AgentCall{}
	for _, c := range calls {
		byID[c.ID] = c
	}
	c := byID["c1"]
	if c.Operation != CallOpClassify || c.AnswerLabel != "PHONE" || c.AnswerConfidence != 0.95 ||
		c.AnswerSensitivity != "PII" || c.ReasonRU != "номера мобильных" || c.Error != "" {
		t.Fatalf("поля classify искажены: %+v", c)
	}
	c = byID["c2"]
	if c.Operation != CallOpVerify || c.Status != "error" || c.Error != "agentproxy: HTTP 500: boom" {
		t.Fatalf("поля verify-error искажены: %+v", c)
	}
	byVerdict, err := st.ListAgentCallsByVerdict(ctx, "v1")
	if err != nil || len(byVerdict) != 2 {
		t.Fatalf("ListAgentCallsByVerdict: %v, %+v", err, byVerdict)
	}
	for _, c := range byVerdict {
		if c.VerdictID != "v1" {
			t.Fatalf("чужой verdict_id: %+v", c)
		}
	}
	if other, _ := st.ListAgentCallsByVerdict(ctx, "ghost"); len(other) != 0 {
		t.Fatalf("чужие вердикты не должны попадать: %+v", other)
	}
}

// TestVerdictFilterLLMStatus — фильтр списка вердиктов по статусу LLM (S9-2).
func TestVerdictFilterLLMStatus(t *testing.T) {
	st := openTest(t)
	ctx := context.Background()
	mustSaveScan(t, st, "s1")
	statuses := []verdict.LLMStatus{
		verdict.LLMStatusCalled, verdict.LLMStatusCacheHit, verdict.LLMStatusCalled,
	}
	for i, ls := range statuses {
		v := testVerdict(fmt.Sprintf("v%d", i+1), "s1")
		v.Path = fmt.Sprintf("col%d", i+1)
		v.LLMStatus = ls
		mustSaveVerdicts(t, st, v)
	}
	vs, total, err := st.ListVerdictsFiltered(ctx, VerdictFilter{ScanID: "s1", LLMStatus: string(verdict.LLMStatusCalled)})
	if err != nil || total != 2 || len(vs) != 2 {
		t.Fatalf("фильтр called: total=%d len=%d err=%v", total, len(vs), err)
	}
	for _, v := range vs {
		if v.LLMStatus != verdict.LLMStatusCalled {
			t.Fatalf("фильтр called пропустил %q: %+v", v.LLMStatus, v)
		}
	}
	vs, total, _ = st.ListVerdictsFiltered(ctx, VerdictFilter{ScanID: "s1", LLMStatus: string(verdict.LLMStatusCacheHit)})
	if total != 1 || len(vs) != 1 || vs[0].Path != "col2" {
		t.Fatalf("фильтр cache_hit: %+v (total=%d)", vs, total)
	}
	// пустой статус — без фильтра
	if _, total, _ = st.ListVerdictsFiltered(ctx, VerdictFilter{ScanID: "s1"}); total != 3 {
		t.Fatalf("без фильтра total=%d, ожидалось 3", total)
	}
}

// TestMigration0011LLMEvidence — up/down/up миграции и бэкфилл llm_status
// исторических строк только по фактам evidence (S9-2): порядок приоритетов
// cluster_propagated > budget_exceeded > small_sample > cache_hit > called,
// недетектируемое остаётся пустым.
func TestMigration0011LLMEvidence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s92.db")
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	// откат на схему 0010 и подготовка «исторических» строк
	db, err := openRaw(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := goose.DownTo(db, "migrations", 10); err != nil {
		db.Close()
		t.Fatal(err)
	}
	_, err = db.Exec(`INSERT INTO scans (id, source_name, profile, status, started_at, stats_json)
		VALUES ('legacy', 'ch', 'deep', 'done', '2026-01-01T00:00:00Z', '{}')`)
	legacy := []struct {
		id   string
		ev   string
		want string
	}{
		{"v-cluster", `{"cluster_propagated":true,"llm":{}}`, "cluster_propagated"},
		{"v-both", `{"cluster_propagated":true,"budget_exceeded":true}`, "cluster_propagated"},
		{"v-budget", `{"budget_exceeded":true,"reason":"small_sample"}`, "budget_exceeded"},
		{"v-small", `{"reason":"small_sample"}`, "small_sample"},
		{"v-cache", `{"llm_cache":{"hit":true}}`, "cache_hit"},
		{"v-called", `{"llm":{"reason_ru":"x"}}`, "called"},
		{"v-none", `{"rules":{}}`, ""},
	}
	for _, r := range legacy {
		if err == nil {
			_, err = db.Exec(`INSERT INTO verdicts
				(id, scan_id, table_name, path, native_type, label, sensitivity, confidence,
				 evidence_layer, evidence, review_status, created_at)
				VALUES (?, 'legacy', 'users', ?, 'String', 'EMAIL', 'PII', 0.9, 'ensemble', ?, 'auto_accepted', '2026-01-01T00:00:00Z')`,
				r.id, r.id, r.ev)
		}
	}
	if err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	// upgrade: миграция 0011 с бэкфиллом
	st, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	for _, r := range legacy {
		v, err := st.GetVerdict(t.Context(), r.id)
		if err != nil {
			t.Fatalf("GetVerdict(%s): %v", r.id, err)
		}
		if string(v.LLMStatus) != r.want {
			t.Fatalf("%s: llm_status=%q, ожидался %q (evidence=%s)", r.id, v.LLMStatus, r.want, r.ev)
		}
	}

	// up/down/up: откат на 0010 и повторный upgrade восстанавливают схему
	db, err = openRaw(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := goose.DownTo(db, "migrations", 10); err != nil {
		db.Close()
		t.Fatalf("down to 10: %v", err)
	}
	if err := goose.Up(db, "migrations"); err != nil {
		db.Close()
		t.Fatalf("up: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	st2, err := Open(path) // no-op миграции, проверка открытия на свежей схеме
	if err != nil {
		t.Fatal(err)
	}
	if calls, err := st2.ListAgentCallsByVerdict(t.Context(), "v-called"); err != nil || len(calls) != 0 {
		t.Fatalf("ListAgentCallsByVerdict после up/down/up: %v, %+v", err, calls)
	}
	st2.Close()
}

// TestAgentCallS92Defaults — старые коды, не знающие новых полей, всё ещё
// проходят: DEFAULT ” / 0 на уровне схемы (обратная совместимость INSERT'ов).
func TestAgentCallS92Defaults(t *testing.T) {
	st := openTest(t)
	ctx := context.Background()
	mustSaveScan(t, st, "s1")
	mustSaveVerdicts(t, st, testVerdict("v1", "s1"))
	if _, err := st.db.Exec(`INSERT INTO agent_calls
		(id, scan_id, verdict_id, agent_id, model, prompt_version, tokens_in, tokens_out,
		 cost_usd, latency_ms, cached, status, created_at)
		VALUES ('old-style', 's1', 'v1', 'zond-main', 'gpt-4o-mini', '1', 10, 5, 0.1, 100, 0, 'ok', ?)`,
		time.Now().UTC().Format(time.RFC3339)); err != nil {
		t.Fatalf("старый INSERT: %v", err)
	}
	calls, err := st.ListAgentCalls(ctx, "s1")
	if err != nil || len(calls) != 1 {
		t.Fatalf("ListAgentCalls: %v, %+v", err, calls)
	}
	c := calls[0]
	if c.Operation != "" || c.AnswerLabel != "" || c.AnswerConfidence != 0 ||
		c.AnswerSensitivity != "" || c.ReasonRU != "" || c.Error != "" {
		t.Fatalf("DEFAULT-значения искажены: %+v", c)
	}
}
