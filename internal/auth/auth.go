// Package auth — аутентификация и авторизация (ADR-0011, blueprint п. 11.3,
// п. 14.2): роли и RBAC-матрица, SSO-сессии в памяти процесса, разрешение
// субъектов (SSO-сессия | API-токен | admin-token fallback) для REST API.
//
// SAML Service Provider — saml.go (инкремент 5в-5).
package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

// Role — роль субъекта (п. 11.3): admin — все действия; viewer — только
// просмотр. Пользователь в обеих группах получает admin (максимальная роль).
type Role string

const (
	RoleAdmin  Role = "admin"
	RoleViewer Role = "viewer"
)

// MaxRole — максимальная роль из набора (п. 11.3: admin+viewer → admin).
func MaxRole(roles ...Role) Role {
	best := RoleViewer
	for _, r := range roles {
		if r == RoleAdmin {
			return RoleAdmin
		}
	}
	return best
}

// Action — защищаемое действие API (RBAC-матрица п. 11.3 + scope'ы токенов
// п. 14.2). Каждый маршрут API объявляет требуемое действие.
type Action string

const (
	ActionView   Action = "view"   // просмотр сканов/вердиктов/дрейфа/стоимости
	ActionExport Action = "export" // экспорт CSV/JSON
	ActionReview Action = "review" // ручное ревью
	ActionScan   Action = "scan"   // старт/стоп сканов
	ActionAudit  Action = "audit"  // просмотр аудита (/audit, audit export)
)

// rbac — матрица «действие × роль» (п. 11.3): admin может всё, viewer —
// только просмотр.
var rbac = map[Action]map[Role]bool{
	ActionView:   {RoleAdmin: true, RoleViewer: true},
	ActionExport: {RoleAdmin: true},
	ActionReview: {RoleAdmin: true},
	ActionScan:   {RoleAdmin: true},
	ActionAudit:  {RoleAdmin: true},
}

// Allows — RBAC-проверка: разрешено ли роли действие (п. 11.3).
func Allows(role Role, a Action) bool { return rbac[a][role] }

// Subject — аутентифицированный субъект запроса (п. 14.2 форматы actor).
type Subject struct {
	Actor string // "sso:<subject>" | "token:<id>" | "admin-token" | "api"
	Role  Role   // для SSO-пользователей — роль из users; admin-token → admin
}

type subjectKey struct{}

// WithSubject кладёт субъекта в ctx (auth-middleware → handlers).
func WithSubject(ctx context.Context, s Subject) context.Context {
	return context.WithValue(ctx, subjectKey{}, s)
}

// SubjectFrom извлекает субъекта из ctx; ok=false — запрос не
// аутентифицирован (middleware обязан отклонить раньше).
func SubjectFrom(ctx context.Context) (Subject, bool) {
	s, ok := ctx.Value(subjectKey{}).(Subject)
	return s, ok
}

// ---------------------------------------------------------------------------
// Сессии SSO (п. 11.3: в памяти процесса; рестарт разлогинивает всех)
// ---------------------------------------------------------------------------

// Session — SSO-сессия после успешного SAML-входа.
type Session struct {
	ID        string
	Subject   string // SAML NameID
	Role      Role
	ExpiresAt time.Time
}

// SessionStore — in-memory хранилище сессий (п. 11.3: single-instance,
// рестарт разлогинивает — приемлемо). Потокобезопасно.
type SessionStore struct {
	mu       sync.Mutex
	sessions map[string]Session
	ttl      time.Duration
	nowFn    func() time.Time
}

// NewSessionStore — ttl сессии (default 12ч; рабочая смена).
func NewSessionStore(ttl time.Duration) *SessionStore {
	if ttl <= 0 {
		ttl = 12 * time.Hour
	}
	return &SessionStore{sessions: map[string]Session{}, ttl: ttl, nowFn: time.Now}
}

// Create выдаёт новую сессию субъекту (crypto/rand id, 32 байта hex).
func (s *SessionStore) Create(subject string, role Role) Session {
	var b [32]byte
	_, _ = rand.Read(b[:])
	sess := Session{
		ID: hex.EncodeToString(b[:]), Subject: subject, Role: role,
		ExpiresAt: s.nowFn().Add(s.ttl),
	}
	s.mu.Lock()
	s.sessions[sess.ID] = sess
	s.mu.Unlock()
	return sess
}

// Get возвращает сессию по id; ok=false — нет или истекла (просроченные
// удаляются лениво при обращении).
func (s *SessionStore) Get(id string) (Session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	if !ok {
		return Session{}, false
	}
	if s.nowFn().After(sess.ExpiresAt) {
		delete(s.sessions, id)
		return Session{}, false
	}
	return sess, true
}

// Delete завершает сессию (logout/SLO, п. 11.3).
func (s *SessionStore) Delete(id string) {
	s.mu.Lock()
	delete(s.sessions, id)
	s.mu.Unlock()
}

// DeleteBySubject завершает все сессии субъекта (IdP-initiated SLO по
// NameID: cookie в SLO-запросе от IdP может отсутствовать, п. 11.3).
func (s *SessionStore) DeleteBySubject(subject string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for id, sess := range s.sessions {
		if sess.Subject == subject {
			delete(s.sessions, id)
			n++
		}
	}
	return n
}

// Len — число живых сессий (наблюдаемость, тесты).
func (s *SessionStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sessions)
}

// SessionCookie — имя cookie сессии (HttpOnly, SameSite=Lax — ACS POST
// от IdP приходит cross-site и должен нести cookie; Secure выставляется
// по флагу TLS-публикации, 5в-5).
const SessionCookie = "zond_session"
