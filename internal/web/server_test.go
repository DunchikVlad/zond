package web

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DunchikVlad/zond/internal/audit"
	"github.com/DunchikVlad/zond/internal/auth"
	"github.com/DunchikVlad/zond/internal/config"
	"github.com/DunchikVlad/zond/internal/verdict"
	"github.com/DunchikVlad/zond/internal/verdict/store"
)

// Тесты веб-UI (инкремент 5г, п. 11.3): рендер страниц, auth/RBAC,
// действия ревью, CSP, отсутствие сырых значений в evidence.

type fakeRunner struct{ started, stopped string }

func (f *fakeRunner) Start(source, profile, actor string) (string, error) {
	f.started = source
	return "scan-1", nil
}
func (f *fakeRunner) Stop(scanID string) error { f.stopped = scanID; return nil }

func testBundle() *config.Bundle {
	return &config.Bundle{
		Connections: &config.Connections{Sources: []config.Source{
			{Name: "ch-test", Type: "clickhouse"},
		}},
		Detectors: &config.Detectors{
			Agents:   []config.AgentSpec{{ID: "zond-main", Model: "gpt-4o-mini", Endpoint: "http://127.0.0.1"}},
			Ensemble: config.EnsembleConfig{TauAccept: 0.8, TauReview: 0.5, Weights: map[string]float64{"meta": 1, "rules": 1.5}},
		},
		Taxonomy: &config.Taxonomy{
			Version: "1.0.0",
			Labels:  []config.LabelDef{{Name: "EMAIL", Sensitivity: "PII"}, {Name: "PHONE", Sensitivity: "PII"}},
		},
	}
}

// fixtureStore — store с прогоном, pending-вердиктом (evidence содержит
// строку «SEKRET» под неизвестным ключом — не должна попасть в HTML) и
// аудит-событием.
func fixtureStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "web.db"))
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	ctx := context.Background()
	if err := st.SaveScan(ctx, &store.Scan{
		ID: "scan-1", SourceName: "ch-test", Profile: "deep", Status: "done",
		StartedAt: time.Now().UTC(), FinishedAt: ptr(time.Now().UTC()),
		StatsJSON: `{"tables_total":1,"tables_done":1}`,
	}); err != nil {
		t.Fatalf("SaveScan: %v", err)
	}
	v := verdict.Verdict{
		ID: "v1", ScanID: "scan-1", Table: "users", Path: "email",
		NativeType: "String", Label: "EMAIL", Sensitivity: verdict.SensitivityPII,
		Confidence: 0.6, EvidenceLayer: verdict.LayerEnsemble,
		ReviewStatus: verdict.StatusPending, SampleSize: 3,
		Evidence: map[string]any{
			"sample": map[string]any{"values": 3, "nulls": 0, "total": 3},
			"reason": "gray", "debug": "SEKRET-RAW-VALUE",
		},
		CreatedAt: time.Now().UTC(),
	}
	if err := st.SaveVerdicts(ctx, []verdict.Verdict{v}); err != nil {
		t.Fatalf("SaveVerdicts: %v", err)
	}
	if err := st.AppendAudit(ctx, []audit.Event{{
		Actor: "cli", Category: audit.CatScan, Action: "scan_start", Target: "scan:scan-1",
	}}); err != nil {
		t.Fatalf("AppendAudit: %v", err)
	}
	return st
}

func ptr(t time.Time) *time.Time { return &t }

func newTestServer(t *testing.T, st *store.Store, sessions *auth.SessionStore, enabled bool, runner *fakeRunner) (*httptest.Server, *Server) {
	t.Helper()
	srv, err := New(st, nil, sessions, enabled, runner, testBundle())
	if err != nil {
		t.Fatalf("web.New: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, srv
}

func get(t *testing.T, client *http.Client, rawURL string) (int, string) {
	t.Helper()
	resp, err := client.Get(rawURL)
	if err != nil {
		t.Fatalf("get %s: %v", rawURL, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// testCSRFToken — double-submit пара cookie+заголовок (п. 14) для тестов
// HTMX-мутаций: middleware сравнивает значения между собой.
const testCSRFToken = "test-csrf-token-0123456789abcdef"

func addCSRF(req *http.Request) {
	req.AddCookie(&http.Cookie{Name: csrfCookie, Value: testCSRFToken})
	req.Header.Set(csrfHeader, testCSRFToken)
}

// TestCSRFProtection — мутация без пары cookie+заголовок → 403 (п. 14);
// с парой — проходит (дальше решает RBAC/логика).
func TestCSRFProtection(t *testing.T) {
	st := fixtureStore(t)
	sessions := auth.NewSessionStore(0)
	runner := &fakeRunner{}
	ts, _ := newTestServer(t, st, sessions, true, runner)
	admin := sessions.Create("admin@example.com", auth.RoleAdmin)
	form := url.Values{"source": {"ch-test"}, "profile": {"deep"}}

	post := func(mut func(*http.Request)) int {
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/scans/start", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: admin.ID})
		if mut != nil {
			mut(req)
		}
		resp, err := (&http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}

	if code := post(nil); code != http.StatusForbidden {
		t.Fatalf("без CSRF-пары: %d (ожидался 403)", code)
	}
	if code := post(func(r *http.Request) { r.Header.Set(csrfHeader, testCSRFToken) }); code != http.StatusForbidden {
		t.Fatalf("заголовок без cookie: %d (ожидался 403)", code)
	}
	if code := post(func(r *http.Request) {
		r.AddCookie(&http.Cookie{Name: csrfCookie, Value: testCSRFToken})
		r.Header.Set(csrfHeader, "другой-токен")
	}); code != http.StatusForbidden {
		t.Fatalf("расхождение cookie/заголовок: %d (ожидался 403)", code)
	}
	if code := post(addCSRF); code != http.StatusFound {
		t.Fatalf("с парой cookie+заголовок: %d (ожидался 302)", code)
	}
	if runner.started != "ch-test" {
		t.Fatalf("runner.started: %q", runner.started)
	}
}

func TestPagesRender(t *testing.T) {
	st := fixtureStore(t)
	sessions := auth.NewSessionStore(0)
	ts, _ := newTestServer(t, st, sessions, false, &fakeRunner{})

	pages := []struct {
		path string
		want string
	}{
		{"/scans", "scan-1"},
		{"/scans/scan-1", "ch-test"},
		{"/verdicts", "users"},
		{"/review", "email"},
		{"/drift", "Дрейф"},
		{"/cost", "Экономика"},
		{"/audit", "Целостность hash-chain: OK"},
		{"/settings", "zond-main"},
		{"/static/style.css", "body"},
		{"/static/htmx.min.js", "htmx"},
	}
	client := ts.Client()
	for _, p := range pages {
		code, body := get(t, client, ts.URL+p.path)
		if code != http.StatusOK {
			t.Fatalf("%s: %d", p.path, code)
		}
		if !strings.Contains(body, p.want) {
			t.Errorf("%s: нет %q в ответе (%.200q)", p.path, p.want, body)
		}
	}
	// индекс → редирект (без следования — проверяем сам 302)
	noRedirect := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := noRedirect.Get(ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/scans" {
		t.Fatalf("/: %d → %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	// CSP (п. 14)
	if v := resp.Header.Get("Content-Security-Policy"); !strings.Contains(v, "default-src 'self'") {
		t.Fatalf("CSP: %q", v)
	}
	// evidence whitelist: сырые значения не рендерятся
	_, body := get(t, client, ts.URL+"/review")
	if strings.Contains(body, "SEKRET-RAW-VALUE") {
		t.Fatal("сырое значение evidence попало в HTML")
	}
	if !strings.Contains(body, "gray") {
		t.Error("маскированный evidence (reason) не отрендерился")
	}
}

func TestAuthRedirectAndRBAC(t *testing.T) {
	st := fixtureStore(t)
	sessions := auth.NewSessionStore(0)
	runner := &fakeRunner{}
	ts, _ := newTestServer(t, st, sessions, true, runner)
	client := ts.Client()

	// без сессии → 302 на /saml/login (п. 11.3), редирект не следуем
	noRedirect := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := noRedirect.Get(ts.URL + "/scans")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/saml/login" {
		t.Fatalf("анон: %d → %q", resp.StatusCode, resp.Header.Get("Location"))
	}

	// viewer: просмотр есть, действия запрещены
	viewer := sessions.Create("viewer@example.com", auth.RoleViewer)
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/scans", nil)
	req.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: viewer.ID})
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("viewer GET /scans: %d", resp.StatusCode)
	}
	form := url.Values{"source": {"ch-test"}, "profile": {"deep"}}
	req, _ = http.NewRequest(http.MethodPost, ts.URL+"/scans/start", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: viewer.ID})
	addCSRF(req)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("viewer POST /scans/start: %d (%.100q)", resp.StatusCode, b)
	}

	// admin: старт через runner, актор — sso:subj
	admin := sessions.Create("admin@example.com", auth.RoleAdmin)
	req, _ = http.NewRequest(http.MethodPost, ts.URL+"/scans/start", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: admin.ID})
	addCSRF(req)
	resp, err = noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound || runner.started != "ch-test" {
		t.Fatalf("admin start: %d, runner.started=%q", resp.StatusCode, runner.started)
	}
}

func TestReviewActions(t *testing.T) {
	st := fixtureStore(t)
	sessions := auth.NewSessionStore(0)
	ts, _ := newTestServer(t, st, sessions, true, nil)

	admin := sessions.Create("admin@example.com", auth.RoleAdmin)
	post := func(path string, form url.Values) (int, string) {
		req, _ := http.NewRequest(http.MethodPost, ts.URL+path, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("HX-Request", "true")
		req.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: admin.ID})
		addCSRF(req)
		resp, err := ts.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}

	code, body := post("/review/v1/action", url.Values{"action": {"confirm"}})
	if code != http.StatusOK || !strings.Contains(body, "Очередь пуста") {
		t.Fatalf("confirm: %d (%.200q)", code, body)
	}
	v, err := st.GetVerdict(context.Background(), "v1")
	if err != nil || v.ReviewStatus != verdict.StatusConfirmed {
		t.Fatalf("вердикт после confirm: %+v, %v", v, err)
	}
	if v.ReviewedBy != "sso:admin@example.com" {
		t.Fatalf("actor ревью: %q", v.ReviewedBy)
	}

	// повторный confirm → конфликт (сообщение в ответе, вердикт не тронут)
	code, body = post("/review/v1/action", url.Values{"action": {"confirm"}})
	if code != http.StatusOK || !strings.Contains(body, "Конфликт") {
		t.Fatalf("повторный confirm: %d (%.200q)", code, body)
	}
}

func TestReviewBulkAndAuditPage(t *testing.T) {
	st := fixtureStore(t)
	sessions := auth.NewSessionStore(0)
	ts, _ := newTestServer(t, st, sessions, true, nil)
	admin := sessions.Create("admin@example.com", auth.RoleAdmin)

	form := url.Values{"action": {"reject"}, "ids": {"v1"}}
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/review/bulk", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("HX-Request", "true")
	req.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: admin.ID})
	addCSRF(req)
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(b), "выполнено 1") {
		t.Fatalf("bulk: %d (%.200q)", resp.StatusCode, b)
	}
	v, _ := st.GetVerdict(context.Background(), "v1")
	if v.ReviewStatus != verdict.StatusRejected {
		t.Fatalf("bulk reject: %+v", v)
	}
}
