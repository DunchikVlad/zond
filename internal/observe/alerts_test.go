// Тесты Evaluator алертинга (п. 17): правила budget_exceeded/pending_backlog/
// llm_unavailable/audit_chain_break, дедуп и закрытие, аудит-события
// (actor scheduler, категория alert) и webhook-доставка.
package observe

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/DunchikVlad/zond/internal/audit"
	"github.com/DunchikVlad/zond/internal/verdict"
	"github.com/DunchikVlad/zond/internal/verdict/store"
)

// auditFilterAlert — фильтр аудит-событий категории alert.
func auditFilterAlert() audit.Filter { return audit.Filter{Category: audit.CatAlert} }

func mustScanStatus(t *testing.T, st *store.Store, id, source, status string, started time.Time) {
	t.Helper()
	if err := st.SaveScan(context.Background(), &store.Scan{
		ID: id, SourceName: source, Profile: "deep", Status: status, StartedAt: started,
	}); err != nil {
		t.Fatalf("SaveScan %s: %v", id, err)
	}
}

func mustSaveVerdict(t *testing.T, st *store.Store, id, scanID string, now time.Time) {
	t.Helper()
	if err := st.SaveVerdicts(context.Background(), []verdict.Verdict{{
		ID: id, ScanID: scanID, Table: "t", Path: id, Label: "EMAIL",
		ReviewStatus: verdict.StatusPending, CreatedAt: now,
	}}); err != nil {
		t.Fatalf("SaveVerdicts %s: %v", id, err)
	}
}

func mustPendingVerdict(t *testing.T, st *store.Store, scanID string, n int, now time.Time) {
	t.Helper()
	id := scanID + "-v" + string(rune('a'+n))
	mustSaveVerdict(t, st, id, scanID, now)
}

func mustCall(t *testing.T, st *store.Store, id, scanID, verdictID, status string, now time.Time) {
	t.Helper()
	if err := st.SaveVerdictsWithCalls(context.Background(), nil, []store.AgentCall{{
		ID: id, ScanID: scanID, VerdictID: verdictID,
		AgentID: "zond-main", Model: "gpt-4o-mini", Status: status, CreatedAt: now,
	}}, nil); err != nil {
		t.Fatalf("call %s: %v", id, err)
	}
}

// TestEvaluatorRules — смешанный сид: ch (budget_exceeded), mg (pending 7 при
// пороге 5), 6 ошибок LLM подряд; audit-chain цел. Ожидаем три открытых
// алерта и три аудит-события alert_raise.
func TestEvaluatorRules(t *testing.T) {
	st := openStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	mustScanStatus(t, st, "ch-1", "ch", "budget_exceeded", now)
	mustScanStatus(t, st, "mg-1", "mongo", "done", now)
	for i := 0; i < 7; i++ {
		mustPendingVerdict(t, st, "mg-1", i, now)
	}
	mustScanStatus(t, st, "ok-1", "ok-source", "done", now) // без нарушений
	// 6 ошибок подряд (агент zond-main).
	mustSaveVerdict(t, st, "v-llm", "ch-1", now)
	for i := 0; i < 6; i++ {
		mustCall(t, st, "call-e"+string(rune('a'+i)), "ch-1", "v-llm", "error", now)
	}

	e := NewEvaluator(st, nil, WithPendingThreshold(5), WithNowFn(func() time.Time { return now }))
	e.Eval(ctx)

	open, err := st.AlertOpenCount(ctx)
	if err != nil || open != 3 {
		t.Fatalf("open = %d/%v, ожидалось 3 (budget, pending, llm)", open, err)
	}
	list, _ := st.AlertList(ctx, "open", 10)
	rules := map[string]string{}
	for _, a := range list {
		rules[a.Rule] = a.Target
	}
	if rules[RuleBudgetExceeded] != "source:ch" {
		t.Errorf("budget target = %v", rules[RuleBudgetExceeded])
	}
	if rules[RulePendingBacklog] != "source:mongo" {
		t.Errorf("pending target = %v", rules[RulePendingBacklog])
	}
	if rules[RuleLLMUnavailable] != "agent:zond-main" {
		t.Errorf("llm target = %v", rules[RuleLLMUnavailable])
	}
	if _, ok := rules[RuleAuditChainBreak]; ok {
		t.Error("audit_chain_break не должен стрелять на целой цепочке")
	}

	// Аудит: три raise от scheduler, категория alert.
	entries, err := st.AuditList(ctx, auditFilterAlert())
	if err != nil {
		t.Fatalf("AuditList: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("аудит-событий alert = %d, ожидалось 3", len(entries))
	}
	for _, en := range entries {
		if en.Actor != "scheduler" || en.Action != "alert_raise" {
			t.Errorf("аудит: actor=%s action=%s", en.Actor, en.Action)
		}
	}
}

// TestEvaluatorDedupAndResolve — второй прогон без изменений не дублирует;
// исчезновение условия закрывает алерт (с аудитом alert_resolve).
func TestEvaluatorDedupAndResolve(t *testing.T) {
	st := openStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	mustScanStatus(t, st, "s1", "ch", "budget_exceeded", now)
	e := NewEvaluator(st, nil, WithNowFn(func() time.Time { return now }))
	e.Eval(ctx)
	e.Eval(ctx) // дедуп: повторный прогон — тот же открытый алерт
	if n, _ := st.AlertOpenCount(ctx); n != 1 {
		t.Fatalf("после дедупа open = %d, ожидалось 1", n)
	}

	// Новый прогон завершён штатно — budget-алерт угас.
	mustScanStatus(t, st, "s2", "ch", "done", now.Add(time.Minute))
	e.Eval(ctx)
	if n, _ := st.AlertOpenCount(ctx); n != 0 {
		t.Fatalf("после угасания open = %d, ожидалось 0", n)
	}
	entries, _ := st.AuditList(ctx, auditFilterAlert())
	var raises, resolves int
	for _, en := range entries {
		switch en.Action {
		case "alert_raise":
			raises++
		case "alert_resolve":
			resolves++
		}
	}
	if raises != 1 || resolves != 1 {
		t.Errorf("raise/resolve = %d/%d, ожидалось 1/1", raises, resolves)
	}
}

// TestEvaluatorWebhook — httptest-сервер получает raised/resolved события.
func TestEvaluatorWebhook(t *testing.T) {
	st := openStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	var mu sync.Mutex
	var events []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var m map[string]any
		_ = json.NewDecoder(r.Body).Decode(&m)
		mu.Lock()
		events = append(events, m)
		mu.Unlock()
	}))
	defer srv.Close()

	e := NewEvaluator(st, nil,
		WithWebhook(NewWebhook(srv.URL, nil)),
		WithNowFn(func() time.Time { return now }))
	e.Eval(ctx) // пустой store — событий нет
	mustScanStatus(t, st, "s1", "ch", "budget_exceeded", now)
	e.Eval(ctx) // raise
	mustScanStatus(t, st, "s2", "ch", "done", now.Add(time.Minute))
	e.Eval(ctx) // resolve

	mu.Lock()
	defer mu.Unlock()
	if len(events) != 2 {
		t.Fatalf("webhook-событий = %d, ожидалось 2 (raised+resolved)", len(events))
	}
	if events[0]["event"] != "raised" || events[0]["rule"] != RuleBudgetExceeded {
		t.Errorf("первое событие: %v", events[0])
	}
	if events[1]["event"] != "resolved" {
		t.Errorf("второе событие: %v", events[1])
	}
	if events[0]["target"] != "source:ch" || events[0]["severity"] != "warning" {
		t.Errorf("поля события: %v", events[0])
	}
}

// TestNewWebhookEmptyURL — пустой URL → nil (доставка отключена).
func TestNewWebhookEmptyURL(t *testing.T) {
	if NewWebhook("", nil) != nil {
		t.Error("пустой URL должен давать nil")
	}
}

// auditBackup пишет событие backup в аудит-store (источник правила).
func auditBackup(t *testing.T, st *store.Store, status, errMsg string, ts time.Time) {
	t.Helper()
	d := map[string]any{"status": status, "path": "/b/x.db"}
	if errMsg != "" {
		d["error"] = errMsg
	}
	if err := st.AppendAudit(context.Background(), []audit.Event{{
		Actor: "scheduler", Category: audit.CatAdmin, Action: "backup",
		Target: "backup:/b/x.db", Details: d, TS: ts,
	}}); err != nil {
		t.Fatalf("AppendAudit backup: %v", err)
	}
}

// TestRuleBackupFailed — четыре сценария: последняя попытка fail; RPO
// нарушен (расписание есть, успешной копии >24ч); свежая ok — тишина;
// расписания нет и попыток не было — тишина.
func TestRuleBackupFailed(t *testing.T) {
	cases := []struct {
		name           string
		backupExpected bool
		seed           func(t *testing.T, st *store.Store, now time.Time)
		expected       bool
	}{
		{
			name:           "последняя попытка неудачна",
			backupExpected: true,
			seed: func(t *testing.T, st *store.Store, now time.Time) {
				auditBackup(t, st, "ok", "", now.Add(-3*time.Hour))
				auditBackup(t, st, "fail", "нет места", now.Add(-time.Hour))
			},
			expected: true,
		},
		{
			name:           "RPO нарушен: успеха не было >24ч",
			backupExpected: true,
			seed: func(t *testing.T, st *store.Store, now time.Time) {
				auditBackup(t, st, "ok", "", now.Add(-25*time.Hour))
			},
			expected: true,
		},
		{
			name:           "расписание есть, попыток не было вообще",
			backupExpected: true,
			seed:           func(t *testing.T, st *store.Store, now time.Time) {},
			expected:       true,
		},
		{
			name:           "свежая успешная копия",
			backupExpected: true,
			seed: func(t *testing.T, st *store.Store, now time.Time) {
				auditBackup(t, st, "ok", "", now.Add(-time.Hour))
			},
			expected: false,
		},
		{
			name:           "нет расписания и попыток — молчим",
			backupExpected: false,
			seed:           func(t *testing.T, st *store.Store, now time.Time) {},
			expected:       false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := openStore(t)
			now := time.Now().UTC()
			tc.seed(t, st, now)
			e := NewEvaluator(st, nil,
				WithBackupExpected(tc.backupExpected),
				WithNowFn(func() time.Time { return now }))
			e.Eval(context.Background())
			open, _ := st.AlertOpenCount(context.Background())
			if tc.expected && open != 1 {
				t.Fatalf("алертов %d, ожидался 1 (backup_failed)", open)
			}
			if !tc.expected && open != 0 {
				list, _ := st.AlertList(context.Background(), "open", 5)
				t.Fatalf("алертов %d, ожидалось 0: %+v", open, list)
			}
		})
	}
}

// TestRuleBackupFailedResolves — после успешной копии алерт закрывается.
func TestRuleBackupFailedResolves(t *testing.T) {
	st := openStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	auditBackup(t, st, "fail", "нет места", now.Add(-2*time.Hour))
	e := NewEvaluator(st, nil, WithBackupExpected(true), WithNowFn(func() time.Time { return now }))
	e.Eval(ctx)
	if n, _ := st.AlertOpenCount(ctx); n != 1 {
		t.Fatalf("после fail: open=%d", n)
	}
	auditBackup(t, st, "ok", "", now.Add(-time.Minute))
	e.Eval(ctx)
	if n, _ := st.AlertOpenCount(ctx); n != 0 {
		t.Fatalf("после ok: open=%d, ожидалось 0", n)
	}
}
