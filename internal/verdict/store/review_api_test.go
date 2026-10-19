// Тесты инкремента 5б: фильтры вердиктов/сканов для API, атомарное ревью
// (вердикт + review_events + аудит одной транзакцией, п. 13/14.2),
// конфликты ревью (п. 11.2 review_conflict), append-only review_events.
package store

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/DunchikVlad/zond/internal/audit"
	"github.com/DunchikVlad/zond/internal/verdict"
)

// mustSaveVerdict — вспомогательная запись вердикта с произвольными полями.
func mustSaveVerdict(t *testing.T, st *Store, v verdict.Verdict) {
	t.Helper()
	if err := st.SaveVerdicts(context.Background(), []verdict.Verdict{v}); err != nil {
		t.Fatalf("SaveVerdicts: %v", err)
	}
}

// ListScans: фильтры status/source, пагинация, порядок «свежие первыми».
func TestListScansFiltersAndPagination(t *testing.T) {
	st := openTest(t)
	ctx := context.Background()
	base := time.Now().UTC().Add(-time.Hour)
	mk := func(id, source, status string, startedAt time.Time) {
		t.Helper()
		err := st.SaveScan(ctx, &Scan{ID: id, SourceName: source, Profile: "quick",
			Status: status, StartedAt: startedAt})
		if err != nil {
			t.Fatalf("SaveScan %s: %v", id, err)
		}
	}
	mk("s1", "ch-prod", "done", base)
	mk("s2", "ch-prod", "running", base.Add(time.Minute))
	mk("s3", "mongo-prod", "done", base.Add(2*time.Minute))

	all, total, err := st.ListScans(ctx, ScanFilter{})
	if err != nil || total != 3 || len(all) != 3 {
		t.Fatalf("all: total=%d len=%d err=%v", total, len(all), err)
	}
	if all[0].ID != "s3" { // свежие первыми
		t.Fatalf("порядок: первым ожидался s3, получено %s", all[0].ID)
	}
	bySrc, total, err := st.ListScans(ctx, ScanFilter{Source: "ch-prod"})
	if err != nil || total != 2 || len(bySrc) != 2 {
		t.Fatalf("source filter: total=%d len=%d err=%v", total, len(bySrc), err)
	}
	byStatus, total, err := st.ListScans(ctx, ScanFilter{Status: "running"})
	if err != nil || total != 1 || byStatus[0].ID != "s2" {
		t.Fatalf("status filter: %+v total=%d err=%v", byStatus, total, err)
	}
	page, total, err := st.ListScans(ctx, ScanFilter{Limit: 1, Offset: 1})
	if err != nil || total != 3 || len(page) != 1 || page[0].ID != "s2" {
		t.Fatalf("pagination: %+v total=%d err=%v", page, total, err)
	}
}

// GetScan: отсутствующий прогон — sql.ErrNoRows (API → scan_not_found).
func TestGetScanNotFound(t *testing.T) {
	st := openTest(t)
	_, err := st.GetScan(context.Background(), "ghost")
	if !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("ожидался ErrNoRows, получено %v", err)
	}
}

// ListVerdictsFiltered: фильтры п. 11.2 и сортировка risk_first.
func TestListVerdictsFiltered(t *testing.T) {
	st := openTest(t)
	ctx := context.Background()
	mustSaveScan(t, st, "s1")
	mk := func(id, label string, sens verdict.Sensitivity, conf float64, status verdict.ReviewStatus) {
		v := testVerdict(id, "s1")
		v.Label, v.Sensitivity, v.Confidence, v.ReviewStatus = verdict.Label(label), sens, conf, status
		v.Path = id
		mustSaveVerdict(t, st, v)
	}
	mk("low-pci", "CARD", verdict.SensitivityPCI, 0.50, verdict.StatusPending)
	mk("hi-pii", "EMAIL", verdict.SensitivityPII, 0.95, verdict.StatusConfirmed)
	mk("mid-pii", "PHONE", verdict.SensitivityPII, 0.70, verdict.StatusPending)
	mk("none", "FREE_TEXT", verdict.SensitivityNone, 0.99, verdict.StatusAutoAccepted)

	// risk_first: PCI/PII первыми, внутри класса — confidence desc
	vs, total, err := st.ListVerdictsFiltered(ctx, VerdictFilter{ScanID: "s1", RiskFirst: true})
	if err != nil || total != 4 || len(vs) != 4 {
		t.Fatalf("risk_first: total=%d len=%d err=%v", total, len(vs), err)
	}
	if vs[0].Sensitivity != verdict.SensitivityPCI {
		t.Fatalf("risk_first: первым ожидался PCI, получено %+v", vs[0])
	}
	if vs[1].Path != "hi-pii" || vs[2].Path != "mid-pii" {
		t.Fatalf("risk_first внутри классов: %s, %s, %s", vs[0].Path, vs[1].Path, vs[2].Path)
	}

	// фильтры label / sensitivity / min_conf / review_status
	vs, total, _ = st.ListVerdictsFiltered(ctx, VerdictFilter{ScanID: "s1", Sensitivity: "PII", MinConf: 0.8})
	if total != 1 || vs[0].Path != "hi-pii" {
		t.Fatalf("sensitivity+min_conf: %+v total=%d", vs, total)
	}
	_, total, _ = st.ListVerdictsFiltered(ctx, VerdictFilter{ScanID: "s1", ReviewStatus: "pending"})
	if total != 2 {
		t.Fatalf("review_status: total=%d", total)
	}
	_, total, _ = st.ListVerdictsFiltered(ctx, VerdictFilter{ScanID: "s1", Label: "PHONE"})
	if total != 1 {
		t.Fatalf("label: total=%d", total)
	}
	_, total, _ = st.ListVerdictsFiltered(ctx, VerdictFilter{ScanID: "s1", Table: "use"}) // LIKE %use%
	if total != 4 {
		t.Fatalf("table LIKE: total=%d", total)
	}
}

// ApplyReview — happy path: статус, final_label, журнал и аудит атомарны.
func TestApplyReviewHappyPath(t *testing.T) {
	st := openTest(t)
	ctx := context.Background()
	mustSaveScan(t, st, "s1")
	mustSaveVerdict(t, st, testVerdict("v1", "s1"))

	now := time.Now().UTC()
	v, err := st.ApplyReview(ctx, "v1", ReviewRelabel, verdict.Label("PERSON_NAME"), "sso:ivan", now)
	if err != nil {
		t.Fatalf("ApplyReview: %v", err)
	}
	if v.ReviewStatus != verdict.StatusRelabelled || v.FinalLabel != "PERSON_NAME" {
		t.Fatalf("вердикт после relabel: %+v", v)
	}
	if v.ReviewedBy != "sso:ivan" || v.ReviewedAt.IsZero() {
		t.Fatalf("reviewed_*: %+v", v)
	}
	// persisted
	got, err := st.GetVerdict(ctx, "v1")
	if err != nil || got.ReviewStatus != verdict.StatusRelabelled || got.FinalLabel != "PERSON_NAME" {
		t.Fatalf("persisted: %+v err=%v", got, err)
	}
	// review_events
	events, err := st.ListReviewEvents(ctx, "v1")
	if err != nil || len(events) != 1 {
		t.Fatalf("review_events: %+v err=%v", events, err)
	}
	if events[0].Action != "relabel" || events[0].FromLabel != "EMAIL" || events[0].ToLabel != "PERSON_NAME" {
		t.Fatalf("review_event: %+v", events[0])
	}
	// аудит (п. 14.2): категория review, цепочка сходится
	entries, err := st.AuditList(ctx, audit.Filter{Category: audit.CatReview})
	if err != nil || len(entries) != 1 || entries[0].Action != "relabel" || entries[0].Actor != "sso:ivan" {
		t.Fatalf("аудит ревью: %+v err=%v", entries, err)
	}
	rep, _ := st.AuditVerify(ctx)
	if !rep.OK() {
		t.Fatalf("цепочка после ревью: %+v", rep)
	}
}

// ApplyReview — конфликты (п. 11.2 код review_conflict) и not-found.
func TestApplyReviewConflicts(t *testing.T) {
	st := openTest(t)
	ctx := context.Background()
	mustSaveScan(t, st, "s1")
	mustSaveVerdict(t, st, testVerdict("v1", "s1"))

	if _, err := st.ApplyReview(ctx, "ghost", ReviewConfirm, "", "api", time.Now()); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("not found: %v", err)
	}
	if _, err := st.ApplyReview(ctx, "v1", ReviewRelabel, "", "api", time.Now()); err == nil {
		t.Fatal("relabel без label должен быть отклонён")
	} else {
		var conflict *ReviewConflict
		if !errors.As(err, &conflict) {
			t.Fatalf("ожидался ReviewConflict: %v", err)
		}
	}
	if _, err := st.ApplyReview(ctx, "v1", ReviewRelabel, "EMAIL", "api", time.Now()); err == nil {
		t.Fatal("relabel на тот же лейбл — конфликт")
	}
	if _, err := st.ApplyReview(ctx, "v1", "bogus", "", "api", time.Now()); err == nil {
		t.Fatal("неизвестное действие — конфликт")
	}
	// confirm дважды — второй конфликтует (уже confirmed)
	if _, err := st.ApplyReview(ctx, "v1", ReviewConfirm, "", "api", time.Now()); err != nil {
		t.Fatalf("первый confirm: %v", err)
	}
	if _, err := st.ApplyReview(ctx, "v1", ReviewConfirm, "", "api", time.Now()); err == nil {
		t.Fatal("повторный confirm — конфликт")
	}
	// конфликты не оставляют следов ни в review_events, ни в аудите
	events, _ := st.ListReviewEvents(ctx, "v1")
	if len(events) != 1 {
		t.Fatalf("конфликты не должны писать review_events: %+v", events)
	}
	entries, _ := st.AuditList(ctx, audit.Filter{Category: audit.CatReview})
	if len(entries) != 1 {
		t.Fatalf("конфликты не должны писать аудит: %+v", entries)
	}
}

// review_events append-only (миграция 0005): UPDATE/DELETE запрещены
// триггерами (защита в глубину, как audit_log п. 14.2).
func TestReviewEventsAppendOnlyTriggers(t *testing.T) {
	st := openTest(t)
	ctx := context.Background()
	mustSaveScan(t, st, "s1")
	mustSaveVerdict(t, st, testVerdict("v1", "s1"))
	if _, err := st.ApplyReview(ctx, "v1", ReviewConfirm, "", "api", time.Now()); err != nil {
		t.Fatalf("ApplyReview: %v", err)
	}
	if _, err := st.db.Exec(`UPDATE review_events SET action = 'reject'`); err == nil {
		t.Fatal("UPDATE review_events должен быть запрещён триггером")
	}
	if _, err := st.db.Exec(`DELETE FROM review_events`); err == nil {
		t.Fatal("DELETE review_events должен быть запрещён триггером")
	}
}

// ScanCostStats — агрегаты экономики (п. 11.2/п. 17): разрез по агентам,
// итоги, доля решённого без LLM.
func TestScanCostStats(t *testing.T) {
	st := openTest(t)
	ctx := context.Background()
	mustSaveScan(t, st, "s1")
	v1, v2 := testVerdict("v1", "s1"), testVerdict("v2", "s1")
	v2.Path = "phone"
	mustSaveVerdict(t, st, v1)
	mustSaveVerdict(t, st, v2)

	mk := func(id, verdictID, status string, tin, tout int, cost float64) AgentCall {
		return AgentCall{ID: id, ScanID: "s1", VerdictID: verdictID, AgentID: "zond-main",
			Model: "gpt-4o-mini", TokensIn: tin, TokensOut: tout, CostUSD: cost,
			Status: status, CreatedAt: time.Now().UTC()}
	}
	calls := []AgentCall{
		mk("c1", "v1", "ok", 1000, 100, 0.0002),
		mk("c2", "v1", "error", 0, 0, 0),
		mk("c3", "v2", "cache_hit", 0, 0, 0),
	}
	if err := st.SaveVerdictsWithCalls(ctx, nil, calls, nil); err != nil {
		t.Fatalf("SaveVerdictsWithCalls: %v", err)
	}
	stats, err := st.ScanCostStats(ctx, "s1")
	if err != nil {
		t.Fatalf("ScanCostStats: %v", err)
	}
	if len(stats.ByAgent) != 1 {
		t.Fatalf("ByAgent: %+v", stats.ByAgent)
	}
	row := stats.ByAgent[0]
	if row.Calls != 2 || row.CacheHits != 1 || row.Errors != 1 || row.TokensIn != 1000 || row.TokensOut != 100 {
		t.Fatalf("агрегаты: %+v", row)
	}
	if stats.Calls != 2 || stats.CacheHits != 1 || stats.TokensIn != 1000 || stats.CostUSD < 0.00019 {
		t.Fatalf("итоги: %+v", stats)
	}
	// 2 вердикта, реальный вызов был только по v1 → no_llm_share = 0.5
	if stats.Columns != 2 || stats.LLMColumns != 1 || stats.NoLLMShare != 0.5 {
		t.Fatalf("no_llm_share: %+v", stats)
	}
}

// VerdictsForExport — лимит export_max_rows (п. 11.2): превышение → nil+total.
func TestVerdictsForExportLimit(t *testing.T) {
	st := openTest(t)
	ctx := context.Background()
	mustSaveScan(t, st, "s1")
	mustSaveVerdict(t, st, testVerdict("v1", "s1"))
	v2 := testVerdict("v2", "s1")
	v2.Path = "phone"
	mustSaveVerdict(t, st, v2)

	vs, total, err := st.VerdictsForExport(ctx, "s1", 10)
	if err != nil || total != 2 || len(vs) != 2 {
		t.Fatalf("под лимитом: len=%d total=%d err=%v", len(vs), total, err)
	}
	vs, total, err = st.VerdictsForExport(ctx, "s1", 1)
	if err != nil || vs != nil || total != 2 {
		t.Fatalf("сверх лимита: vs=%v total=%d err=%v", vs, total, err)
	}
}
