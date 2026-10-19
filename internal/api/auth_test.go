// Тесты аутентификации/авторизации REST API (инкремент 5в-3/5в-4,
// blueprint п. 11.2, п. 11.3, п. 14.2): цепочка SSO-сессия → Bearer-токен →
// admin-token fallback; RBAC 401/403 с аудитом; actor propagation в мутации;
// режим без SSO — прозрачный (5б).
package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DunchikVlad/zond/internal/audit"
	"github.com/DunchikVlad/zond/internal/auth"
	"github.com/DunchikVlad/zond/internal/verdict"
	"github.com/DunchikVlad/zond/internal/verdict/store"
)

// authedServer — сервер с включённой аутентификацией и выпущенными токенами.
func authedServer(t *testing.T, adminToken string) (*Server, *store.Store, map[string]string) {
	t.Helper()
	srv, st := newTestServer(t, WithAuth(AuthConfig{
		Enabled:    true,
		AdminToken: adminToken,
		Sessions:   auth.NewSessionStore(time.Hour),
	}))
	keys := map[string]string{}
	issue := func(id string, scopes ...store.Scope) {
		key := store.GenerateTokenKey()
		if _, err := st.IssueToken(t.Context(), id, id, scopes, key, "test", time.Now().UTC(), 0); err != nil {
			t.Fatalf("issue %s: %v", id, err)
		}
		keys[id] = key
	}
	issue("reader", store.ScopeRead)
	issue("exporter", store.ScopeExport)
	issue("reviewer", store.ScopeReview)
	issue("admin-tok", store.ScopeAdmin)
	return srv, st, keys
}

func bearer(key string) map[string]string { return map[string]string{"Authorization": "Bearer " + key} }

func doAuth(t *testing.T, srv *Server, method, path, body string, headers map[string]string) int {
	t.Helper()
	var rdr *strings.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	} else {
		rdr = strings.NewReader("")
	}
	req := httptest.NewRequest(method, path, rdr)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	return rec.Code
}

// Без включённого SSO поведение 5б сохраняется: всё открыто, actor "api".
func TestAuthDisabledPassthrough(t *testing.T) {
	srv, st := newTestServer(t)
	mustScan(t, st, "s1", "ch", "done")
	if code := do(t, srv, "GET", "/api/v1/scans", "").Code; code != http.StatusOK {
		t.Fatalf("без SSO должно быть 200: %d", code)
	}
	mustVerdict(t, st, "v1", "s1", "EMAIL", verdict.SensitivityPII, 0.9)
	rec := do(t, srv, "POST", "/api/v1/verdicts/v1/review", `{"action":"confirm"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("review: %d", rec.Code)
	}
	entries, _ := st.AuditList(t.Context(), audit.Filter{Category: audit.CatReview})
	if len(entries) != 1 || entries[0].Actor != Actor {
		t.Fatalf("actor без SSO = api: %+v", entries)
	}
}

// Без креденшелов при включённом SSO — 401, отказ аудируется (п. 14.2 auth).
func TestAuthRequired401(t *testing.T) {
	srv, st, _ := authedServer(t, "")
	if code := doAuth(t, srv, "GET", "/api/v1/scans", "", nil); code != http.StatusUnauthorized {
		t.Fatalf("ожидался 401: %d", code)
	}
	entries, _ := st.AuditList(t.Context(), audit.Filter{Category: audit.CatAuth})
	if len(entries) != 1 || entries[0].Action != "api_auth_failure" {
		t.Fatalf("аудит 401: %+v", entries)
	}
}

// Невалидный Bearer — 401 (не проваливаемся в admin-token fallback).
func TestInvalidBearer401(t *testing.T) {
	srv, _, _ := authedServer(t, "master-key")
	code := doAuth(t, srv, "GET", "/api/v1/scans", "", bearer("zt_wrong"))
	if code != http.StatusUnauthorized {
		t.Fatalf("невалидный токен: %d", code)
	}
}

// RBAC по scope: read — только просмотр; export/review — свои действия;
// admin — всё. Отказы 403 аудируются (п. 14.2 authorization).
func TestRBACByScope(t *testing.T) {
	srv, st, keys := authedServer(t, "")
	mustScan(t, st, "s1", "ch", "done")
	mustVerdict(t, st, "v1", "s1", "EMAIL", verdict.SensitivityPII, 0.9)

	// reader: view OK, export/review/scan — 403
	if code := doAuth(t, srv, "GET", "/api/v1/verdicts?scan_id=s1", "", bearer(keys["reader"])); code != http.StatusOK {
		t.Fatalf("reader view: %d", code)
	}
	if code := doAuth(t, srv, "GET", "/api/v1/export?scan_id=s1", "", bearer(keys["reader"])); code != http.StatusForbidden {
		t.Fatalf("reader export: %d", code)
	}
	if code := doAuth(t, srv, "POST", "/api/v1/verdicts/v1/review", `{"action":"confirm"}`, bearer(keys["reader"])); code != http.StatusForbidden {
		t.Fatalf("reader review: %d", code)
	}
	// exporter: export OK, review — 403
	if code := doAuth(t, srv, "GET", "/api/v1/export?scan_id=s1&format=json", "", bearer(keys["exporter"])); code != http.StatusOK {
		t.Fatalf("exporter export: %d", code)
	}
	if code := doAuth(t, srv, "POST", "/api/v1/verdicts/v1/review", `{"action":"confirm"}`, bearer(keys["exporter"])); code != http.StatusForbidden {
		t.Fatalf("exporter review: %d", code)
	}
	// reviewer: review OK
	if code := doAuth(t, srv, "POST", "/api/v1/verdicts/v1/review", `{"action":"confirm"}`, bearer(keys["reviewer"])); code != http.StatusOK {
		t.Fatalf("reviewer review: %d", code)
	}
	// admin scope: скан-стоп (действие scan) OK
	mustScan(t, st, "scan-running", "ch", "running")
	runner := &fakeRunner{started: map[string]string{"scan-running": "ch"}}
	srv.runner = runner
	if code := doAuth(t, srv, "POST", "/api/v1/scans/scan-running/stop", "", bearer(keys["admin-tok"])); code != http.StatusAccepted {
		t.Fatalf("admin scan stop: %d", code)
	}
	// отказы 403 аудируются с actor/ролью/действием
	entries, _ := st.AuditList(t.Context(), audit.Filter{Category: audit.CatAuthz})
	if len(entries) != 3 {
		t.Fatalf("ожидалось 3 отказа 403 в аудите: %+v", entries)
	}
	for _, e := range entries {
		if e.Action != "forbidden" || e.Details["actor"] == nil || e.Details["action"] == nil {
			t.Fatalf("запись 403 неполная: %+v", e)
		}
	}
	// цепочка сходится
	rep, _ := st.AuditVerify(t.Context())
	if !rep.OK() {
		t.Fatalf("цепочка: %+v", rep)
	}
}

// Actor propagation: действия токена пишутся в аудит как token:<id> (п. 14.2).
func TestActorPropagationToken(t *testing.T) {
	srv, st, keys := authedServer(t, "")
	mustScan(t, st, "s1", "ch", "done")
	mustVerdict(t, st, "v1", "s1", "EMAIL", verdict.SensitivityPII, 0.9)

	if code := doAuth(t, srv, "POST", "/api/v1/verdicts/v1/review", `{"action":"confirm"}`, bearer(keys["reviewer"])); code != http.StatusOK {
		t.Fatalf("review: %d", code)
	}
	entries, _ := st.AuditList(t.Context(), audit.Filter{Category: audit.CatReview})
	if len(entries) != 1 || entries[0].Actor != "token:reviewer" {
		t.Fatalf("actor: %+v", entries)
	}
	// reviewed_by в вердикте — тот же actor
	v, _ := st.GetVerdict(t.Context(), "v1")
	if v.ReviewedBy != "token:reviewer" {
		t.Fatalf("reviewed_by: %+v", v.ReviewedBy)
	}
	// review_events — тоже
	events, _ := st.ListReviewEvents(t.Context(), "v1")
	if len(events) != 1 || events[0].Actor != "token:reviewer" {
		t.Fatalf("review_events: %+v", events)
	}
}

// Admin-token fallback (п. 11.3): доступ admin, каждое использование — аудит
// warn (п. 14.2 «каждое использование admin-токена — всегда warn»).
func TestAdminTokenFallback(t *testing.T) {
	srv, st, _ := authedServer(t, "master-key")
	mustScan(t, st, "s1", "ch", "done")

	hdr := map[string]string{"X-Admin-Token": "master-key"}
	if code := doAuth(t, srv, "GET", "/api/v1/export?scan_id=s1", "", hdr); code != http.StatusOK {
		t.Fatalf("admin-token export: %d", code)
	}
	entries, _ := st.AuditList(t.Context(), audit.Filter{Category: audit.CatAuth})
	var found bool
	for _, e := range entries {
		if e.Action == "admin_token_used" {
			found = true
			if e.Details["level"] != "warn" {
				t.Fatalf("admin-token warn: %+v", e)
			}
		}
	}
	if !found {
		t.Fatalf("admin_token_used не записан: %+v", entries)
	}
	// неверный admin-token — 401
	if code := doAuth(t, srv, "GET", "/api/v1/export?scan_id=s1", "", map[string]string{"X-Admin-Token": "wrong"}); code != http.StatusUnauthorized {
		t.Fatalf("неверный admin-token: %d", code)
	}
	// отключённый fallback (пустой токен) — 401 даже с верным заголовком
	srv2, _, _ := authedServer(t, "")
	if code := doAuth(t, srv2, "GET", "/api/v1/scans", "", map[string]string{"X-Admin-Token": "master-key"}); code != http.StatusUnauthorized {
		t.Fatalf("fallback отключён: %d", code)
	}
}

// SSO-сессия (cookie): субъект sso:<name>, роль из сессии (5в-5 дополнит
// выдачу через SAML; здесь сессия создаётся напрямую — контракт middleware).
func TestSSOSessionSubject(t *testing.T) {
	srv, st, _ := authedServer(t, "")
	sess := srv.auth.Sessions.Create("ivan@corp", auth.RoleViewer)
	mustScan(t, st, "s1", "ch", "done")
	mustVerdict(t, st, "v1", "s1", "EMAIL", verdict.SensitivityPII, 0.9)

	cookie := map[string]string{"Cookie": auth.SessionCookie + "=" + sess.ID}
	if code := doAuth(t, srv, "GET", "/api/v1/verdicts?scan_id=s1", "", cookie); code != http.StatusOK {
		t.Fatalf("sso view: %d", code)
	}
	// viewer не может ревью (п. 11.3)
	if code := doAuth(t, srv, "POST", "/api/v1/verdicts/v1/review", `{"action":"confirm"}`, cookie); code != http.StatusForbidden {
		t.Fatalf("sso viewer review: %d", code)
	}
	// admin-сессия может; actor — sso:ivan@corp
	sess2 := srv.auth.Sessions.Create("boss@corp", auth.RoleAdmin)
	cookie2 := map[string]string{"Cookie": auth.SessionCookie + "=" + sess2.ID}
	if code := doAuth(t, srv, "POST", "/api/v1/verdicts/v1/review", `{"action":"confirm"}`, cookie2); code != http.StatusOK {
		t.Fatalf("sso admin review: %d", code)
	}
	entries, _ := st.AuditList(t.Context(), audit.Filter{Category: audit.CatReview})
	if len(entries) != 1 || entries[0].Actor != "sso:boss@corp" {
		t.Fatalf("actor sso: %+v", entries)
	}
	// протухшая/несуществующая сессия — 401
	if code := doAuth(t, srv, "GET", "/api/v1/scans", "", map[string]string{"Cookie": auth.SessionCookie + "=deadbeef"}); code != http.StatusUnauthorized {
		t.Fatalf("мёртвая сессия: %d", code)
	}
}

// Health/ready не требуют аутентификации (liveness для оркестратора).
func TestHealthOpenUnderAuth(t *testing.T) {
	srv, _, _ := authedServer(t, "")
	if code := doAuth(t, srv, "GET", "/api/health", "", nil); code != http.StatusOK {
		t.Fatalf("health открыт: %d", code)
	}
	if code := doAuth(t, srv, "GET", "/api/ready", "", nil); code != http.StatusOK {
		t.Fatalf("ready открыт: %d", code)
	}
}
