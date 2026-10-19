// E2E-тесты REST API v1 (blueprint п. 11.2) поверх реального store:
// маршруты, конверт ошибок, фильтры, ревью (audit 1:1), экспорт (лимит,
// аудит до выдачи), correlation id, health/ready.
package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DunchikVlad/zond/internal/audit"
	"github.com/DunchikVlad/zond/internal/verdict"
	"github.com/DunchikVlad/zond/internal/verdict/store"
)

// fakeRunner — тестовый ScanRunner.
type fakeRunner struct {
	started  map[string]string // scan_id → source
	stopped  []string
	startErr error
}

func (f *fakeRunner) Start(source, _, _ string) (string, error) {
	if f.startErr != nil {
		return "", f.startErr
	}
	id := "scan-" + source
	f.started[id] = source
	return id, nil
}

func (f *fakeRunner) Stop(scanID string) error {
	if _, ok := f.started[scanID]; !ok {
		return errors.New("не исполняется")
	}
	f.stopped = append(f.stopped, scanID)
	return nil
}

func newTestServer(t *testing.T, opts ...Option) (*Server, *store.Store) {
	t.Helper()
	st, err := store.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	srv := New(st, nil, opts...)
	return srv, st
}

func mustScan(t *testing.T, st *store.Store, id, source, status string) {
	t.Helper()
	err := st.SaveScan(t.Context(), &store.Scan{
		ID: id, SourceName: source, Profile: "quick", Status: status,
		StartedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("SaveScan: %v", err)
	}
}

func mustVerdict(t *testing.T, st *store.Store, id, scanID, label string, sens verdict.Sensitivity, conf float64) {
	t.Helper()
	v := verdict.Verdict{
		ID: id, ScanID: scanID, Table: "users", Path: id, NativeType: "String",
		Label: verdict.Label(label), Sensitivity: sens, Confidence: conf,
		EvidenceLayer: verdict.LayerEnsemble, Evidence: map[string]any{"sample": "m***@example.com"},
		ReviewStatus: verdict.StatusPending, CreatedAt: time.Now().UTC(),
	}
	if err := st.SaveVerdicts(t.Context(), []verdict.Verdict{v}); err != nil {
		t.Fatalf("SaveVerdicts: %v", err)
	}
}

func do(t *testing.T, srv *Server, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, rdr)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	return rec
}

func decode(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("ответ не JSON: %v: %s", err, rec.Body.String())
	}
	return m
}

// Здоровье: liveness всегда 200, readiness — 200 при доступном store.
func TestHealthReady(t *testing.T) {
	srv, _ := newTestServer(t)
	if rec := do(t, srv, "GET", "/api/health", ""); rec.Code != http.StatusOK {
		t.Fatalf("health: %d", rec.Code)
	}
	rec := do(t, srv, "GET", "/api/ready", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("ready: %d: %s", rec.Code, rec.Body.String())
	}
}

// Correlation id: генерируется и возвращается; входящий — принимается (п. 14.1).
func TestCorrelationID(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := do(t, srv, "GET", "/api/health", "")
	if rec.Header().Get("X-Request-ID") == "" {
		t.Fatal("X-Request-ID не выставлен")
	}
	req := httptest.NewRequest("GET", "/api/health", nil)
	req.Header.Set("X-Request-ID", "test-cid-42")
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Header().Get("X-Request-ID") != "test-cid-42" {
		t.Fatalf("входящий X-Request-ID потерян: %q", rec.Header().Get("X-Request-ID"))
	}
}

// Сканы: список с фильтрами и карточка; 404 в конверте п. 11.2.
func TestScanListAndGet(t *testing.T) {
	srv, st := newTestServer(t)
	mustScan(t, st, "s1", "ch-prod", "done")
	mustScan(t, st, "s2", "mongo-prod", "running")

	rec := do(t, srv, "GET", "/api/v1/scans", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("list: %d", rec.Code)
	}
	m := decode(t, rec)
	if m["total"].(float64) != 2 {
		t.Fatalf("total: %v", m["total"])
	}
	rec = do(t, srv, "GET", "/api/v1/scans?status=running", "")
	if m := decode(t, rec); m["total"].(float64) != 1 {
		t.Fatalf("status filter: %v", m["total"])
	}
	rec = do(t, srv, "GET", "/api/v1/scans/s1", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("get: %d", rec.Code)
	}
	m = decode(t, rec)
	scan := m["scan"].(map[string]any)
	if scan["id"] != "s1" || scan["status"] != "done" {
		t.Fatalf("scan: %v", scan)
	}
	rec = do(t, srv, "GET", "/api/v1/scans/ghost", "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("404: %d", rec.Code)
	}
	env := decode(t, rec)
	errObj := env["error"].(map[string]any)
	if errObj["code"] != "scan_not_found" {
		t.Fatalf("конверт ошибки: %v", env)
	}
}

// Старт/стоп: 202 + scan_id; stop аудируется; конфликт на не-running.
func TestScanStartStop(t *testing.T) {
	runner := &fakeRunner{started: map[string]string{}}
	srv, st := newTestServer(t, WithRunner(runner))
	mustScan(t, st, "scan-ch", "ch-prod", "running")

	rec := do(t, srv, "POST", "/api/v1/scans", `{"source":"ch","profile":"deep"}`)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("start: %d: %s", rec.Code, rec.Body.String())
	}
	if m := decode(t, rec); m["scan_id"] != "scan-ch" {
		t.Fatalf("scan_id: %v", m)
	}
	// пустой source — 400 в конверте
	if rec := do(t, srv, "POST", "/api/v1/scans", `{}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("empty source: %d", rec.Code)
	}
	// стоп running-прогона → 202, аудит scan_stop
	rec = do(t, srv, "POST", "/api/v1/scans/scan-ch/stop", "")
	if rec.Code != http.StatusAccepted {
		t.Fatalf("stop: %d: %s", rec.Code, rec.Body.String())
	}
	entries, err := st.AuditList(t.Context(), audit.Filter{Category: audit.CatScan})
	if err != nil || len(entries) != 1 || entries[0].Action != "scan_stop" || entries[0].Actor != Actor {
		t.Fatalf("аудит stop: %+v err=%v", entries, err)
	}
	if len(runner.stopped) != 1 || runner.stopped[0] != "scan-ch" {
		t.Fatalf("runner.Stop: %v", runner.stopped)
	}
	// повторный stop (прогон уже не running в store) — 409
	mustScan(t, st, "scan-done", "ch-prod", "done")
	if rec := do(t, srv, "POST", "/api/v1/scans/scan-done/stop", ""); rec.Code != http.StatusConflict {
		t.Fatalf("stop done: %d", rec.Code)
	}
}

// Вердикты: фильтры п. 11.2, сортировка risk_first, карточка 404.
func TestVerdictList(t *testing.T) {
	srv, st := newTestServer(t)
	mustScan(t, st, "s1", "ch", "done")
	mustVerdict(t, st, "v1", "s1", "CARD", verdict.SensitivityPCI, 0.5)
	mustVerdict(t, st, "v2", "s1", "EMAIL", verdict.SensitivityPII, 0.95)
	mustVerdict(t, st, "v3", "s1", "FREE_TEXT", verdict.SensitivityNone, 0.99)

	rec := do(t, srv, "GET", "/api/v1/verdicts?scan_id=s1&sort=risk_first", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("list: %d", rec.Code)
	}
	items := decode(t, rec)["items"].([]any)
	if len(items) != 3 {
		t.Fatalf("items: %d", len(items))
	}
	first := items[0].(map[string]any)
	if first["sensitivity"] != "PCI" {
		t.Fatalf("risk_first: первым ожидался PCI: %v", first["sensitivity"])
	}
	rec = do(t, srv, "GET", "/api/v1/verdicts?scan_id=s1&min_conf=0.9&sensitivity=PII", "")
	if m := decode(t, rec); m["total"].(float64) != 1 {
		t.Fatalf("min_conf+sensitivity: %v", m["total"])
	}
	// битый min_conf — 400
	if rec := do(t, srv, "GET", "/api/v1/verdicts?min_conf=abc", ""); rec.Code != http.StatusBadRequest {
		t.Fatalf("min_conf: %d", rec.Code)
	}
	// карточка: evidence отдаётся (маскирован на записи, ADR-0010)
	rec = do(t, srv, "GET", "/api/v1/verdicts/v2", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("get: %d", rec.Code)
	}
	v := decode(t, rec)["verdict"].(map[string]any)
	if v["id"] != "v2" || v["evidence"].(map[string]any)["sample"] != "m***@example.com" {
		t.Fatalf("verdict: %v", v)
	}
	if rec := do(t, srv, "GET", "/api/v1/verdicts/ghost", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("404: %d", rec.Code)
	}
}

// Ревью: happy path (статус+журнал+аудит), конфликт 409 review_conflict,
// валидация тела (п. 11.2).
func TestReview(t *testing.T) {
	srv, st := newTestServer(t)
	mustScan(t, st, "s1", "ch", "done")
	mustVerdict(t, st, "v1", "s1", "EMAIL", verdict.SensitivityPII, 0.9)

	rec := do(t, srv, "POST", "/api/v1/verdicts/v1/review", `{"action":"relabel","label":"PERSON_NAME"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("review: %d: %s", rec.Code, rec.Body.String())
	}
	v := decode(t, rec)["verdict"].(map[string]any)
	if v["review_status"] != "relabelled" || v["final_label"] != "PERSON_NAME" {
		t.Fatalf("verdict: %v", v)
	}
	if v["reviewed_by"] != Actor {
		t.Fatalf("actor: %v", v["reviewed_by"])
	}
	// журнал ревью виден в карточке
	rec = do(t, srv, "GET", "/api/v1/verdicts/v1", "")
	events := decode(t, rec)["review_events"].([]any)
	if len(events) != 1 || events[0].(map[string]any)["action"] != "relabel" {
		t.Fatalf("review_events: %v", events)
	}
	// аудит review (п. 14.2)
	entries, _ := st.AuditList(t.Context(), audit.Filter{Category: audit.CatReview})
	if len(entries) != 1 || entries[0].Actor != Actor || entries[0].Action != "relabel" {
		t.Fatalf("аудит: %+v", entries)
	}
	// повторный relabel на тот же лейбл — 409 review_conflict
	rec = do(t, srv, "POST", "/api/v1/verdicts/v1/review", `{"action":"relabel","label":"PERSON_NAME"}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("conflict: %d", rec.Code)
	}
	if decode(t, rec)["error"].(map[string]any)["code"] != "review_conflict" {
		t.Fatalf("код: %s", rec.Body.String())
	}
	// relabel без label — 400
	if rec := do(t, srv, "POST", "/api/v1/verdicts/v1/review", `{"action":"relabel"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("no label: %d", rec.Code)
	}
	// неизвестный вердикт — 404
	if rec := do(t, srv, "POST", "/api/v1/verdicts/ghost/review", `{"action":"confirm"}`); rec.Code != http.StatusNotFound {
		t.Fatalf("ghost: %d", rec.Code)
	}
}

// Экспорт: JSON/CSV, аудит до выдачи (fail-closed п. 14.2), лимит строк,
// неизвестный прогон.
func TestExport(t *testing.T) {
	srv, st := newTestServer(t)
	mustScan(t, st, "s1", "ch", "done")
	mustVerdict(t, st, "v1", "s1", "EMAIL", verdict.SensitivityPII, 0.9)

	rec := do(t, srv, "GET", "/api/v1/export?scan_id=s1&format=json", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("export json: %d", rec.Code)
	}
	if m := decode(t, rec); m["total"].(float64) != 1 {
		t.Fatalf("total: %v", m["total"])
	}
	// аудит экспорта записан ДО выдачи (здесь: записан вообще, цепочка сходится)
	entries, _ := st.AuditList(t.Context(), audit.Filter{Category: audit.CatExport})
	if len(entries) != 1 || entries[0].Action != "verdicts_export" {
		t.Fatalf("аудит экспорта: %+v", entries)
	}
	// CSV
	rec = do(t, srv, "GET", "/api/v1/export?scan_id=s1&format=csv", "")
	if rec.Code != http.StatusOK || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/csv") {
		t.Fatalf("csv: %d %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	body := rec.Body.String()
	if !strings.Contains(body, "\"id\",\"scan_id\"") && !strings.Contains(body, "id,scan_id") {
		t.Fatalf("csv header: %s", body)
	}
	if !strings.Contains(body, "v1") || !strings.Contains(body, "EMAIL") {
		t.Fatalf("csv rows: %s", body)
	}
	// формат по умолчанию — json; неизвестный прогон — 404; без scan_id — 400
	if rec := do(t, srv, "GET", "/api/v1/export", ""); rec.Code != http.StatusBadRequest {
		t.Fatalf("no scan_id: %d", rec.Code)
	}
	if rec := do(t, srv, "GET", "/api/v1/export?scan_id=ghost", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("ghost: %d", rec.Code)
	}
}

// Лимит экспорта: сверх export_max_rows — 409 с предложением async (п. 11.2).
func TestExportLimit(t *testing.T) {
	srv, st := newTestServer(t, WithExportMaxRows(1))
	mustScan(t, st, "s1", "ch", "done")
	mustVerdict(t, st, "v1", "s1", "EMAIL", verdict.SensitivityPII, 0.9)
	mustVerdict(t, st, "v2", "s1", "PHONE", verdict.SensitivityPII, 0.8)

	rec := do(t, srv, "GET", "/api/v1/export?scan_id=s1", "")
	if rec.Code != http.StatusConflict {
		t.Fatalf("limit: %d: %s", rec.Code, rec.Body.String())
	}
	errObj := decode(t, rec)["error"].(map[string]any)
	if errObj["details"].(map[string]any)["async"] != true {
		t.Fatalf("async hint: %v", errObj)
	}
	// отказ экспорта не аудируется как выдача (данных не было)
	entries, _ := st.AuditList(t.Context(), audit.Filter{Category: audit.CatExport})
	if len(entries) != 0 {
		t.Fatalf("отказанный экспорт не должен аудироваться как выдача: %+v", entries)
	}
}

// Экономика: GET /api/v1/stats/cost (п. 11.2/п. 17).
func TestCost(t *testing.T) {
	srv, st := newTestServer(t)
	mustScan(t, st, "s1", "ch", "done")
	mustVerdict(t, st, "v1", "s1", "EMAIL", verdict.SensitivityPII, 0.9)
	calls := []store.AgentCall{{
		ID: "c1", ScanID: "s1", VerdictID: "v1", AgentID: "zond-main", Model: "gpt-4o-mini",
		TokensIn: 1000, TokensOut: 100, CostUSD: 0.0002, Status: "ok", CreatedAt: time.Now().UTC(),
	}}
	if err := st.SaveVerdictsWithCalls(t.Context(), nil, calls, nil); err != nil {
		t.Fatalf("calls: %v", err)
	}
	rec := do(t, srv, "GET", "/api/v1/stats/cost?scan_id=s1", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("cost: %d", rec.Code)
	}
	m := decode(t, rec)
	if m["calls"].(float64) != 1 || m["tokens_in"].(float64) != 1000 {
		t.Fatalf("stats: %v", m)
	}
	byAgent := m["by_agent"].([]any)
	if len(byAgent) != 1 || byAgent[0].(map[string]any)["model"] != "gpt-4o-mini" {
		t.Fatalf("by_agent: %v", byAgent)
	}
	if rec := do(t, srv, "GET", "/api/v1/stats/cost", ""); rec.Code != http.StatusBadRequest {
		t.Fatalf("no scan_id: %d", rec.Code)
	}
}

// Дрейф: два прогона источника — дифф; один — 404 (п. 11.2).
func TestDrift(t *testing.T) {
	srv, st := newTestServer(t)
	mustScan(t, st, "s1", "ch", "done")
	mustVerdict(t, st, "v1", "s1", "EMAIL", verdict.SensitivityPII, 0.9)
	time.Sleep(10 * time.Millisecond) // порядок started_at
	mustScan(t, st, "s2", "ch", "done")
	mustVerdict(t, st, "v1", "s2", "EMAIL", verdict.SensitivityPII, 0.9)
	mustVerdict(t, st, "v2", "s2", "PHONE", verdict.SensitivityPII, 0.8)

	rec := do(t, srv, "GET", "/api/v1/drift?source=ch", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("drift: %d: %s", rec.Code, rec.Body.String())
	}
	m := decode(t, rec)
	if m["base_scan_id"] != "s1" || m["curr_scan_id"] != "s2" {
		t.Fatalf("пара: %v", m)
	}
	added := m["added"].([]any)
	if len(added) != 1 || added[0].(map[string]any)["path"] != "v2" {
		t.Fatalf("added: %v", added)
	}
	// source_id — алиас (blueprint п. 11.2)
	if rec := do(t, srv, "GET", "/api/v1/drift?source_id=ch", ""); rec.Code != http.StatusOK {
		t.Fatalf("source_id alias: %d", rec.Code)
	}
	if rec := do(t, srv, "GET", "/api/v1/drift?source=mongo", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("no pair: %d", rec.Code)
	}
	if rec := do(t, srv, "GET", "/api/v1/drift", ""); rec.Code != http.StatusBadRequest {
		t.Fatalf("no source: %d", rec.Code)
	}
}

// Цепочка аудита после всех операций сходится (п. 14.2).
func TestAuditChainIntactAfterAPI(t *testing.T) {
	srv, st := newTestServer(t)
	mustScan(t, st, "s1", "ch", "done")
	mustVerdict(t, st, "v1", "s1", "EMAIL", verdict.SensitivityPII, 0.9)
	do(t, srv, "POST", "/api/v1/verdicts/v1/review", `{"action":"confirm"}`)
	do(t, srv, "GET", "/api/v1/export?scan_id=s1", "")
	rep, err := st.AuditVerify(t.Context())
	if err != nil || !rep.OK() || rep.Checked != 2 {
		t.Fatalf("цепочка: %+v err=%v", rep, err)
	}
}
