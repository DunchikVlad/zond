// Аутентификация и авторизация REST API (инкремент 5в, blueprint п. 11.2,
// п. 11.3, п. 14.2): цепочка разрешения субъекта — SSO-сессия (5в-5) →
// Bearer API-токен → admin-token fallback; RBAC по матрице п. 11.3; отказы
// 401/403 аудируются (auth/authorization).
package api

import (
	"net/http"
	"strings"

	"github.com/DunchikVlad/zond/internal/audit"
	"github.com/DunchikVlad/zond/internal/auth"
	"github.com/DunchikVlad/zond/internal/verdict/store"
)

// scopeToAction — отображение scope токена на действие RBAC (п. 14.2:
// read | review | export | admin; просмотр аудита — только admin).
var scopeToAction = map[store.Scope]auth.Action{
	store.ScopeRead:   auth.ActionView,
	store.ScopeExport: auth.ActionExport,
	store.ScopeReview: auth.ActionReview,
}

// tokenAllows — токен разрешает действие, если имеет соответствующий scope
// (admin включает всё — см. APIToken.HasScope). Аудит — только scope admin.
func tokenAllows(t *store.APIToken, a auth.Action) bool {
	if t.HasScope(store.ScopeAdmin) {
		return true
	}
	for sc, act := range scopeToAction {
		if act == a && t.HasScope(sc) {
			return true
		}
	}
	// scan (старт/стоп) отдельного scope нет — только admin (п. 14.2).
	return false
}

// AuthConfig — настройка аутентификации сервера (инкремент 5в).
type AuthConfig struct {
	Enabled bool // sso.enabled из connections.yaml
	// AdminToken — аварийный доступ (env CLASSIFIER_ADMIN_TOKEN, п. 11.3);
	// пустой или admin_token_fallback=false → отключён.
	AdminToken string
	Sessions   *auth.SessionStore // nil → SSO-сессии не принимаются
}

// withAuth — middleware аутентификации: разрешает субъекта запроса.
// При выключенном SSO (dev-контур) — пропускает как api.Actor (режим 5б).
// При включённом: cookie-сессия → Bearer-токен → admin-token; иначе 401.
func (s *Server) withAuth(next http.Handler) http.Handler {
	if s.auth == nil || !s.auth.Enabled {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// liveness/readiness и SSO-эндпоинты — без аутентификации: health —
		// для оркестратора/проб (п. 15), /saml/* — точки входа входа и
		// приёмка ACS/SLO от IdP (анонимность по построению протокола, 5в-5).
		if r.URL.Path == "/api/health" || r.URL.Path == "/api/ready" ||
			strings.HasPrefix(r.URL.Path, "/saml/") {
			next.ServeHTTP(w, r)
			return
		}
		subj, ok := s.resolveSubject(r)
		if !ok {
			// Неудача аутентификации — аудируемое событие (п. 14.2 auth;
			// без actor — субъект не установлен; best effort, не fail-closed,
			// чтобы отказ отдать клиенту в любом случае).
			_ = s.auditEvent(r.Context(), audit.CatAuth, "api_auth_failure", "api", map[string]any{
				"path": r.URL.Path, "method": r.Method,
			})
			writeError(w, http.StatusUnauthorized, CodeInvalidRequest,
				"требуется аутентификация (SSO-сессия или API-токен)", nil)
			return
		}
		next.ServeHTTP(w, r.WithContext(auth.WithSubject(r.Context(), subj)))
	})
}

// resolveSubject — цепочка разрешения субъекта (п. 11.3, п. 14.2).
func (s *Server) resolveSubject(r *http.Request) (auth.Subject, bool) {
	// 1. SSO-сессия (cookie) — 5в-5.
	if s.auth.Sessions != nil {
		if c, err := r.Cookie(auth.SessionCookie); err == nil {
			if sess, ok := s.auth.Sessions.Get(c.Value); ok {
				return auth.Subject{Actor: "sso:" + sess.Subject, Role: sess.Role}, true
			}
		}
	}
	// 2. Bearer API-токен (п. 14.2).
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		key := strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))
		if t, err := s.st.ResolveToken(r.Context(), key, s.nowFn()); err == nil {
			return auth.Subject{Actor: "token:" + t.ID, Role: tokenRole(t)}, true
		}
		return auth.Subject{}, false // невалидный Bearer — не проваливаемся в fallback
	}
	// 3. Admin-token fallback (п. 11.3: bootstrap/аварийный; каждое
	// использование аудируется уровнем warn — п. 14.2).
	if s.auth.AdminToken != "" {
		if h := r.Header.Get("X-Admin-Token"); h != "" && h == s.auth.AdminToken {
			_ = s.auditEvent(r.Context(), audit.CatAuth, "admin_token_used", "api", map[string]any{
				"path": r.URL.Path, "method": r.Method, "level": "warn",
			})
			return auth.Subject{Actor: "admin-token", Role: auth.RoleAdmin}, true
		}
	}
	return auth.Subject{}, false
}

// tokenRole — роль для RBAC: scope admin → admin, иначе viewer (п. 11.3
// две роли; review/export-скопы дают действия без полной роли admin —
// проверка действий для токенов идёт через tokenAllows).
func tokenRole(t *store.APIToken) auth.Role {
	if t.HasScope(store.ScopeAdmin) {
		return auth.RoleAdmin
	}
	return auth.RoleViewer
}

// requireAction — middleware авторизации (RBAC п. 11.3): субъект из ctx
// (withAuth обязан идти раньше) проверяется по матрице; SSO-субъекты —
// по роли, токены — по scope (admin-token имеет роль admin). Отказ 403
// аудируется (п. 14.2 authorization: роль, ресурс, subject).
func (s *Server) requireAction(a auth.Action, h http.HandlerFunc) http.HandlerFunc {
	if s.auth == nil || !s.auth.Enabled {
		return h
	}
	return func(w http.ResponseWriter, r *http.Request) {
		subj, ok := auth.SubjectFrom(r.Context())
		if !ok {
			writeError(w, http.StatusUnauthorized, CodeInvalidRequest,
				"требуется аутентификация", nil)
			return
		}
		if !s.subjectAllows(r, subj, a) {
			_ = s.auditEvent(r.Context(), audit.CatAuthz, "forbidden", "api", map[string]any{
				"actor": subj.Actor, "role": string(subj.Role), "action": string(a),
				"path": r.URL.Path, "method": r.Method,
			})
			writeError(w, http.StatusForbidden, CodeInvalidRequest,
				"недостаточно прав (требуется "+string(a)+")", nil)
			return
		}
		h(w, r)
	}
}

// subjectAllows — проверка действия: для токенов — по scope, для остальных
// субъектов — по роли (п. 11.3).
func (s *Server) subjectAllows(r *http.Request, subj auth.Subject, a auth.Action) bool {
	if strings.HasPrefix(subj.Actor, "token:") {
		t, err := s.st.ResolveToken(r.Context(), bearerKey(r), s.nowFn())
		if err != nil {
			return false
		}
		return tokenAllows(t, a)
	}
	return auth.Allows(subj.Role, a)
}

// bearerKey извлекает ключ из заголовка (уже проверенного в resolveSubject).
func bearerKey(r *http.Request) string {
	h := r.Header.Get("Authorization")
	return strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))
}

// actorFromCtx — actor аудит-событий мутаций: субъект запроса, либо "api"
// (режим без SSO, инкремент 5б).
func (s *Server) actorFromCtx(r *http.Request) string {
	if subj, ok := auth.SubjectFrom(r.Context()); ok {
		return subj.Actor
	}
	return Actor
}
