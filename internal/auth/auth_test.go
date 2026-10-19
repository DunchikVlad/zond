package auth

import (
	"testing"
	"time"
)

// RBAC-матрица п. 11.3: admin — всё, viewer — только просмотр.
func TestRBACMatrix(t *testing.T) {
	cases := []struct {
		role   Role
		action Action
		want   bool
	}{
		{RoleAdmin, ActionView, true},
		{RoleAdmin, ActionExport, true},
		{RoleAdmin, ActionReview, true},
		{RoleAdmin, ActionScan, true},
		{RoleAdmin, ActionAudit, true},
		{RoleViewer, ActionView, true},
		{RoleViewer, ActionExport, false},
		{RoleViewer, ActionReview, false},
		{RoleViewer, ActionScan, false},
		{RoleViewer, ActionAudit, false},
	}
	for _, c := range cases {
		if got := Allows(c.role, c.action); got != c.want {
			t.Errorf("Allows(%s, %s) = %v, ожидалось %v", c.role, c.action, got, c.want)
		}
	}
}

// Пользователь в группах admin и viewer получает admin (п. 11.3).
func TestMaxRole(t *testing.T) {
	if MaxRole(RoleViewer, RoleAdmin) != RoleAdmin {
		t.Fatal("admin+viewer → admin")
	}
	if MaxRole(RoleViewer) != RoleViewer {
		t.Fatal("viewer → viewer")
	}
	if MaxRole() != RoleViewer {
		t.Fatal("пустой набор → viewer (минимальная)")
	}
}

// Сессии: создание, получение, истечение TTL, logout (п. 11.3 in-memory).
func TestSessionStoreLifecycle(t *testing.T) {
	st := NewSessionStore(time.Hour)
	sess := st.Create("ivan@corp", RoleAdmin)
	if sess.ID == "" || sess.Subject != "ivan@corp" || sess.Role != RoleAdmin {
		t.Fatalf("сессия: %+v", sess)
	}
	got, ok := st.Get(sess.ID)
	if !ok || got.ID != sess.ID {
		t.Fatalf("Get: %+v ok=%v", got, ok)
	}
	st.Delete(sess.ID)
	if _, ok := st.Get(sess.ID); ok {
		t.Fatal("после Delete сессия должна исчезнуть")
	}
}

// Просроченная сессия недействительна и удаляется лениво.
func TestSessionExpiry(t *testing.T) {
	st := NewSessionStore(time.Hour)
	past := time.Now().Add(-2 * time.Hour)
	st.nowFn = func() time.Time { return past }
	sess := st.Create("ivan@corp", RoleViewer)
	st.nowFn = time.Now // «вернулись в настоящее» — сессия просрочена
	if _, ok := st.Get(sess.ID); ok {
		t.Fatal("просроченная сессия не должна возвращаться")
	}
	if st.Len() != 0 {
		t.Fatalf("просроченная удаляется лениво: %d", st.Len())
	}
}

// Субъект в ctx: round-trip.
func TestSubjectContext(t *testing.T) {
	ctx := t.Context()
	if _, ok := SubjectFrom(ctx); ok {
		t.Fatal("пустой ctx: субъекта быть не должно")
	}
	ctx = WithSubject(ctx, Subject{Actor: "sso:ivan@corp", Role: RoleAdmin})
	s, ok := SubjectFrom(ctx)
	if !ok || s.Actor != "sso:ivan@corp" || s.Role != RoleAdmin {
		t.Fatalf("round-trip: %+v ok=%v", s, ok)
	}
}
