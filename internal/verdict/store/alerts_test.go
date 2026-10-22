// Тесты журнала алертов (миграция 0007): дедуп открытых по (rule, target),
// продление, закрытие не-активных, список, счётчик открытых.
package store

import (
	"context"
	"testing"
	"time"
)

func TestAlertRaiseDedupAndTouch(t *testing.T) {
	st := openTest(t)
	ctx := context.Background()
	now := time.Now().UTC()

	created, err := st.AlertRaise(ctx, "budget_exceeded", "warning", "source:ch", "m1", map[string]any{"a": 1}, now)
	if err != nil || !created {
		t.Fatalf("первый подъём: created=%v err=%v, ожидалось true/nil", created, err)
	}
	// Повтор того же (rule, target) — не дублируется.
	created, err = st.AlertRaise(ctx, "budget_exceeded", "warning", "source:ch", "m2", map[string]any{"a": 2}, now.Add(time.Minute))
	if err != nil || created {
		t.Fatalf("повторный подъём: created=%v err=%v, ожидалось false/nil", created, err)
	}
	// Другая цель — новый алерт.
	created, _ = st.AlertRaise(ctx, "budget_exceeded", "warning", "source:mg", "m3", nil, now)
	if !created {
		t.Fatal("другая цель: ожидался новый алерт")
	}
	open, err := st.AlertOpenCount(ctx)
	if err != nil || open != 2 {
		t.Fatalf("open count = %d/%v, ожидалось 2", open, err)
	}
	// Продление обновило message/details.
	list, _ := st.AlertList(ctx, "open", 10)
	if len(list) != 2 {
		t.Fatalf("list = %d, ожидалось 2", len(list))
	}
	for _, a := range list {
		if a.Target == "source:ch" {
			if a.Message != "m2" || a.Details["a"] != float64(2) {
				t.Errorf("продление не применилось: %+v", a)
			}
			if !a.LastSeen.After(a.CreatedAt) {
				t.Errorf("last_seen_at не продлён: created=%v seen=%v", a.CreatedAt, a.LastSeen)
			}
		}
	}
}

func TestAlertResolveNotIn(t *testing.T) {
	st := openTest(t)
	ctx := context.Background()
	now := time.Now().UTC()

	mustRaise := func(rule, severity, target string) {
		t.Helper()
		created, err := st.AlertRaise(ctx, rule, severity, target, "m", nil, now)
		if err != nil || !created {
			t.Fatalf("AlertRaise %s/%s: created=%v err=%v", rule, target, created, err)
		}
	}
	mustRaise("pending_backlog", "warning", "source:ch")
	mustRaise("llm_unavailable", "critical", "agent:zond-main")
	// source:ch больше не стреляет — закрывается; агент остаётся активным.
	resolved, err := st.AlertResolveNotIn(ctx,
		[]string{"pending_backlog", "llm_unavailable"},
		map[string]bool{"llm_unavailable:agent:zond-main": true}, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("AlertResolveNotIn: %v", err)
	}
	if len(resolved) != 1 || resolved[0].Target != "source:ch" {
		t.Fatalf("resolved = %+v, ожидался один source:ch", resolved)
	}
	open, _ := st.AlertOpenCount(ctx)
	if open != 1 {
		t.Errorf("open после закрытия = %d, ожидалось 1", open)
	}
	// Закрытый виден в списке с resolved_at; повторный прогон без активных —
	// закрывает остаток.
	all, _ := st.AlertList(ctx, "", 10)
	var closed, withResolved int
	for _, a := range all {
		if a.State == "resolved" {
			closed++
			if a.Resolved != nil {
				withResolved++
			}
		}
	}
	if closed != 1 || withResolved != 1 {
		t.Errorf("closed/withResolved = %d/%d, ожидалось 1/1", closed, withResolved)
	}
	resolved, _ = st.AlertResolveNotIn(ctx,
		[]string{"pending_backlog", "llm_unavailable"}, map[string]bool{}, now.Add(2*time.Minute))
	if len(resolved) != 1 || resolved[0].Rule != "llm_unavailable" {
		t.Errorf("второе закрытие: %+v", resolved)
	}
	if n, _ := st.AlertOpenCount(ctx); n != 0 {
		t.Errorf("open в конце = %d, ожидалось 0", n)
	}
}

func TestAlertListFilter(t *testing.T) {
	st := openTest(t)
	ctx := context.Background()
	now := time.Now().UTC()
	mustRaise2 := func(rule, severity, target string) {
		t.Helper()
		if _, err := st.AlertRaise(ctx, rule, severity, target, "m", nil, now); err != nil {
			t.Fatalf("AlertRaise %s/%s: %v", rule, target, err)
		}
	}
	mustRaise2("audit_chain_break", "critical", "audit_log")
	mustRaise2("budget_exceeded", "warning", "source:ch")
	if _, err := st.AlertResolveNotIn(ctx, []string{"audit_chain_break"}, map[string]bool{}, now.Add(time.Minute)); err != nil {
		t.Fatalf("AlertResolveNotIn: %v", err)
	}

	open, _ := st.AlertList(ctx, "open", 0)
	if len(open) != 1 || open[0].Rule != "budget_exceeded" {
		t.Errorf("open-фильтр: %+v", open)
	}
	resolved, _ := st.AlertList(ctx, "resolved", 0)
	if len(resolved) != 1 || resolved[0].Rule != "audit_chain_break" {
		t.Errorf("resolved-фильтр: %+v", resolved)
	}
}
