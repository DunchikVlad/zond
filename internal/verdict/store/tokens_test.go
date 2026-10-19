// Тесты инкремента 5в-1: users (JIT upsert), api_tokens (выпуск, resolve
// по ключу, мгновенный отзыв, троттлинг last_used_at, аудит admin).
package store

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/DunchikVlad/zond/internal/audit"
)

// UpsertUser: JIT-создание при первом входе, обновление роли/display_name
// при повторном (смена групп в IdP применяется при каждом входе, п. 11.3).
func TestUpsertUserJIT(t *testing.T) {
	st := openTest(t)
	ctx := context.Background()
	now := time.Now().UTC()

	u := &User{Subject: "ivan@corp", DisplayName: "Иван", Role: "viewer"}
	if err := st.UpsertUser(ctx, u, now); err != nil {
		t.Fatalf("первый upsert: %v", err)
	}
	got, err := st.GetUser(ctx, "ivan@corp")
	if err != nil || got.Role != "viewer" || got.DisplayName != "Иван" {
		t.Fatalf("после JIT: %+v err=%v", got, err)
	}
	if got.CreatedAt.IsZero() || got.LastLoginAt.IsZero() {
		t.Fatalf("timestamps: %+v", got)
	}
	created := got.CreatedAt

	// повторный вход с новой ролью (admin) и именем
	u2 := &User{Subject: "ivan@corp", DisplayName: "Иван И.", Role: "admin"}
	if err := st.UpsertUser(ctx, u2, now.Add(time.Hour)); err != nil {
		t.Fatalf("второй upsert: %v", err)
	}
	got, _ = st.GetUser(ctx, "ivan@corp")
	if got.Role != "admin" || got.DisplayName != "Иван И." {
		t.Fatalf("роль не обновилась: %+v", got)
	}
	if !got.CreatedAt.Equal(created) {
		t.Fatalf("created_at не должен меняться: %+v", got)
	}
	if !got.LastLoginAt.After(created) {
		t.Fatalf("last_login_at не обновился: %+v", got)
	}
}

func TestGetUserNotFound(t *testing.T) {
	st := openTest(t)
	_, err := st.GetUser(context.Background(), "ghost")
	if !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("ожидался ErrNoRows: %v", err)
	}
}

// IssueToken + ResolveToken: ключ сверяется argon2id-хэшем, аудит выпуска
// в той же транзакции, last_used_at троттлится до раза в час (п. 14.2).
func TestIssueAndResolveToken(t *testing.T) {
	st := openTest(t)
	ctx := context.Background()
	now := time.Now().UTC()

	key := GenerateTokenKey()
	tok, err := st.IssueToken(ctx, "t1", "ci-bot", []Scope{ScopeRead, ScopeExport}, key, "sso:admin", now, 0)
	if err != nil {
		t.Fatalf("IssueToken: %v", err)
	}
	if tok.ExpiresAt.Sub(tok.CreatedAt) != 90*24*time.Hour {
		t.Fatalf("default TTL 90д: %+v", tok)
	}
	// аудит token_issue (п. 14.2 администрирование)
	entries, err := st.AuditList(ctx, auditFilterAdmin())
	if err != nil || len(entries) != 1 || entries[0].Action != "token_issue" || entries[0].Actor != "sso:admin" {
		t.Fatalf("аудит выпуска: %+v err=%v", entries, err)
	}

	// resolve по ключу
	got, err := st.ResolveToken(ctx, key, now)
	if err != nil {
		t.Fatalf("ResolveToken: %v", err)
	}
	if got.ID != "t1" || !got.HasScope(ScopeRead) || !got.HasScope(ScopeExport) || got.HasScope(ScopeReview) {
		t.Fatalf("scopes: %+v", got)
	}
	// admin включает все scope
	if !(&APIToken{Scopes: []Scope{ScopeAdmin}}).HasScope(ScopeExport) {
		t.Fatal("admin scope должен включать остальные")
	}
	// чужой ключ не подходит
	if _, err := st.ResolveToken(ctx, GenerateTokenKey(), now); !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("чужой ключ: %v", err)
	}
	// last_used_at выставлен при первом использовании
	if got.LastUsedAt == nil {
		t.Fatal("last_used_at не выставлен")
	}
	// повторный resolve в пределах часа не двигает last_used_at
	got2, _ := st.ResolveToken(ctx, key, now.Add(30*time.Minute))
	if !got2.LastUsedAt.Equal(*got.LastUsedAt) {
		t.Fatalf("троттлинг last_used_at: %+v vs %+v", got2.LastUsedAt, got.LastUsedAt)
	}
	// через час — обновляется
	got3, _ := st.ResolveToken(ctx, key, now.Add(2*time.Hour))
	if !got3.LastUsedAt.After(*got.LastUsedAt) {
		t.Fatalf("last_used_at должен обновиться через час: %+v", got3.LastUsedAt)
	}
}

// RevokeToken — мгновенный отзыв (п. 14.2): ключ сразу не резолвится,
// повторный отзыв — ошибка, аудит token_revoke.
func TestRevokeToken(t *testing.T) {
	st := openTest(t)
	ctx := context.Background()
	now := time.Now().UTC()
	key := GenerateTokenKey()
	if _, err := st.IssueToken(ctx, "t1", "ci", []Scope{ScopeRead}, key, "cli", now, 0); err != nil {
		t.Fatalf("issue: %v", err)
	}
	if err := st.RevokeToken(ctx, "t1", "sso:admin", now); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := st.ResolveToken(ctx, key, now.Add(time.Minute)); !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("отозванный ключ: %v", err)
	}
	if err := st.RevokeToken(ctx, "t1", "cli", now); err == nil {
		t.Fatal("повторный отзыв должен падать")
	}
	entries, _ := st.AuditList(ctx, auditFilterAdmin())
	actions := map[string]bool{}
	for _, e := range entries {
		actions[e.Action] = true
	}
	if !actions["token_issue"] || !actions["token_revoke"] {
		t.Fatalf("аудит: %+v", entries)
	}
	// цепочка аудита сходится
	rep, _ := st.AuditVerify(ctx)
	if !rep.OK() {
		t.Fatalf("цепочка: %+v", rep)
	}
}

// Просроченный токен недействителен (п. 14.2: срок действия).
func TestExpiredTokenInvalid(t *testing.T) {
	st := openTest(t)
	ctx := context.Background()
	now := time.Now().UTC()
	key := GenerateTokenKey()
	if _, err := st.IssueToken(ctx, "t1", "short", []Scope{ScopeRead}, key, "cli", now, time.Hour); err != nil {
		t.Fatalf("issue: %v", err)
	}
	if _, err := st.ResolveToken(ctx, key, now.Add(2*time.Hour)); !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("просроченный: %v", err)
	}
}

// Валидация scopes при выпуске.
func TestIssueTokenValidatesScopes(t *testing.T) {
	st := openTest(t)
	ctx := context.Background()
	now := time.Now().UTC()
	if _, err := st.IssueToken(ctx, "t1", "x", nil, GenerateTokenKey(), "cli", now, 0); err == nil {
		t.Fatal("пустые scopes должны падать")
	}
	if _, err := st.IssueToken(ctx, "t2", "x", []Scope{"bogus"}, GenerateTokenKey(), "cli", now, 0); err == nil {
		t.Fatal("неизвестный scope должен падать")
	}
	// неуспешные выпуски не аудируются как совершённые
	entries, _ := st.AuditList(ctx, auditFilterAdmin())
	if len(entries) != 0 {
		t.Fatalf("аудит: %+v", entries)
	}
}

// ListTokens не раскрывает хэши и показывает revoked-флаг.
func TestListTokens(t *testing.T) {
	st := openTest(t)
	ctx := context.Background()
	now := time.Now().UTC()
	k1, k2 := GenerateTokenKey(), GenerateTokenKey()
	_, _ = st.IssueToken(ctx, "t1", "a", []Scope{ScopeRead}, k1, "cli", now, 0)
	_, _ = st.IssueToken(ctx, "t2", "b", []Scope{ScopeAdmin}, k2, "cli", now.Add(time.Second), 0)
	_ = st.RevokeToken(ctx, "t2", "cli", now.Add(2*time.Second))

	toks, err := st.ListTokens(ctx)
	if err != nil || len(toks) != 2 {
		t.Fatalf("list: %+v err=%v", toks, err)
	}
	if toks[0].ID != "t2" || toks[0].RevokedAt == nil { // свежие первыми
		t.Fatalf("порядок/revoked: %+v", toks[0])
	}
	if toks[1].ID != "t1" || toks[1].RevokedAt != nil {
		t.Fatalf("t1: %+v", toks[1])
	}
}

func auditFilterAdmin() audit.Filter {
	return audit.Filter{Category: audit.CatAdmin}
}
