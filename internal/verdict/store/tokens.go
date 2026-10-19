// Пользователи SSO и API-токены (blueprint п. 11.1, п. 14.2, ADR-0011):
// JIT-прvisioning users при первом SAML-входе; api_tokens — программный
// доступ в обход SSO (CI/интеграции), хранение только хэшем ключа (argon2id),
// отзыв мгновенный, last_used_at троттлится до раза в час.
package store

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/DunchikVlad/zond/internal/audit"
	"golang.org/x/crypto/argon2"
)

// ---------------------------------------------------------------------------
// users — JIT-прvisioning из SAML (п. 11.3)
// ---------------------------------------------------------------------------

// User — строка users (п. 11.1): SSO-субъект с ролью.
type User struct {
	Subject     string    `json:"subject"` // SAML NameID
	DisplayName string    `json:"display_name"`
	Role        string    `json:"role"` // admin | viewer
	LastLoginAt time.Time `json:"last_login_at"`
	CreatedAt   time.Time `json:"created_at"`
}

// UpsertUser создаёт пользователя при первом входе (JIT) или обновляет
// display_name/role/last_login_at при повторном (роль маппится из
// SAML-атрибутов при КАЖДОМ входе — п. 11.3; смена групп в IdP
// применяется без ручной синхронизации).
func (s *Store) UpsertUser(ctx context.Context, u *User, now time.Time) error {
	ts := now.UTC().Format(time.RFC3339)
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO users (subject, display_name, role, last_login_at, created_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT (subject) DO UPDATE SET
		  display_name = excluded.display_name, role = excluded.role,
		  last_login_at = excluded.last_login_at`,
		u.Subject, u.DisplayName, u.Role, ts, ts)
	return err
}

// GetUser возвращает пользователя по subject; sql.ErrNoRows, если не найден.
func (s *Store) GetUser(ctx context.Context, subject string) (*User, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT subject, display_name, role, last_login_at, created_at
		FROM users WHERE subject = ?`, subject)
	var u User
	var lastLogin, created string
	if err := row.Scan(&u.Subject, &u.DisplayName, &u.Role, &lastLogin, &created); err != nil {
		return nil, err
	}
	u.LastLoginAt, _ = time.Parse(time.RFC3339, lastLogin)
	u.CreatedAt, _ = time.Parse(time.RFC3339, created)
	return &u, nil
}

// ListUsers — все пользователи (администрирование; /settings этапа 5г).
func (s *Store) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT subject, display_name, role, last_login_at, created_at
		FROM users ORDER BY subject`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		var u User
		var lastLogin, created string
		if err := rows.Scan(&u.Subject, &u.DisplayName, &u.Role, &lastLogin, &created); err != nil {
			return nil, err
		}
		u.LastLoginAt, _ = time.Parse(time.RFC3339, lastLogin)
		u.CreatedAt, _ = time.Parse(time.RFC3339, created)
		out = append(out, u)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------------------
// api_tokens — программный доступ (п. 14.2)
// ---------------------------------------------------------------------------

// Scope — область доступа API-токена (п. 14.2: read|review|export|admin).
type Scope string

const (
	ScopeRead   Scope = "read"
	ScopeReview Scope = "review"
	ScopeExport Scope = "export"
	ScopeAdmin  Scope = "admin"
)

// APIToken — строка api_tokens (ключа здесь нет — только хэш).
type APIToken struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Scopes     []Scope    `json:"scopes"`
	IssuedBy   string     `json:"issued_by"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  time.Time  `json:"expires_at"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
}

// HasScope проверяет наличие scope; admin включает все остальные (п. 14.2
// scope admin — полный программный доступ).
func (t *APIToken) HasScope(s Scope) bool {
	for _, sc := range t.Scopes {
		if sc == ScopeAdmin || sc == s {
			return true
		}
	}
	return false
}

// Параметры argon2id (OWASP cheat sheet, memory-hard; п. 14.2 «argon2»).
const (
	argonTime    = 1
	argonMemory  = 64 * 1024 // 64 MiB
	argonThreads = 4
	argonKeyLen  = 32
	argonSaltLen = 16
)

// hashTokenKey — argon2id(key, salt): memory-hard хэш ключа токена.
// Формат хранения: "argon2id$<salt_hex>$<hash_hex>".
func hashTokenKey(key string, salt []byte) string {
	h := argon2.IDKey([]byte(key), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("argon2id$%s$%s", hex.EncodeToString(salt), hex.EncodeToString(h))
}

// verifyTokenKey сверяет ключ с хранимым хэшем (constant-time по хэшу).
func verifyTokenKey(key, stored string) bool {
	parts := strings.SplitN(stored, "$", 3)
	if len(parts) != 3 || parts[0] != "argon2id" {
		return false
	}
	salt, err := hex.DecodeString(parts[1])
	if err != nil {
		return false
	}
	want, err := hex.DecodeString(parts[2])
	if err != nil {
		return false
	}
	got := argon2.IDKey([]byte(key), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return subtle.ConstantTimeCompare(got, want) == 1
}

// GenerateTokenKey — новый ключ API-токена: "zt_" + base64url(32 байта).
// Показывается владельцу ОДИН РАЗ при выпуске (п. 14.2).
func GenerateTokenKey() string {
	var b [32]byte
	_, _ = rand.Read(b[:])
	return "zt_" + base64.RawURLEncoding.EncodeToString(b[:])
}

// IssueToken выпускает API-токен: ключ генерируется снаружи (показывается
// один раз), в БД — только argon2id-хэш. ttl по умолчанию 90 дней (п. 14.2).
// Выпуск — аудируемое действие (admin/token_issue) — пишется той же
// транзакцией (п. 13/14.2).
func (s *Store) IssueToken(ctx context.Context, id, name string, scopes []Scope, key, issuedBy string, now time.Time, ttl time.Duration) (*APIToken, error) {
	if ttl <= 0 {
		ttl = 90 * 24 * time.Hour
	}
	if len(scopes) == 0 {
		return nil, errors.New("scopes: ожидается хотя бы одна область (read|review|export|admin)")
	}
	var csvs []string
	for _, sc := range scopes {
		switch sc {
		case ScopeRead, ScopeReview, ScopeExport, ScopeAdmin:
			csvs = append(csvs, string(sc))
		default:
			return nil, fmt.Errorf("неизвестный scope %q", sc)
		}
	}
	salt := make([]byte, argonSaltLen)
	_, _ = rand.Read(salt)
	t := &APIToken{
		ID: id, Name: name, Scopes: scopes, IssuedBy: issuedBy,
		CreatedAt: now.UTC(), ExpiresAt: now.UTC().Add(ttl),
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO api_tokens (id, name, scopes, key_hash, issued_by, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		t.ID, t.Name, strings.Join(csvs, ","), hashTokenKey(key, salt), t.IssuedBy,
		t.CreatedAt.Format(time.RFC3339), t.ExpiresAt.Format(time.RFC3339)); err != nil {
		return nil, err
	}
	if err := appendAuditTokenEvent(ctx, tx, issuedBy, "token_issue", "token:"+t.ID, map[string]any{
		"name": t.Name, "scopes": csvs, "expires_at": t.ExpiresAt.Format(time.RFC3339),
	}, now); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return t, nil
}

// ErrTokenInvalid — ключ не найден, отозван или просрочен (п. 14.2: отзыв
// мгновенный). API отображает в 401, без детализации причины наружу.
var ErrTokenInvalid = errors.New("токен недействителен")

// ResolveToken находит токен по ключу: полный перебор кандидатов не нужен —
// ключ ищется по префиксному индексу невозможно (хэш), поэтому id токена
// кодируется в ключ? Нет: ключ самодостаточен — сверка идёт по всем
// неотозванным токенам (их мало, п. 14.2). Возвращает токен и обновляет
// last_used_at не чаще раза в час (п. 14.2).
func (s *Store) ResolveToken(ctx context.Context, key string, now time.Time) (*APIToken, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, name, scopes, key_hash, issued_by, created_at, expires_at, revoked_at, last_used_at
		FROM api_tokens WHERE revoked_at = ''`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var candidates []APIToken
	var hashes []string
	for rows.Next() {
		var t APIToken
		var scopesCSV, keyHash, created, expires, revoked, lastUsed string
		if err := rows.Scan(&t.ID, &t.Name, &scopesCSV, &keyHash, &t.IssuedBy,
			&created, &expires, &revoked, &lastUsed); err != nil {
			return nil, err
		}
		t.CreatedAt, _ = time.Parse(time.RFC3339, created)
		t.ExpiresAt, _ = time.Parse(time.RFC3339, expires)
		if lastUsed != "" {
			lu, _ := time.Parse(time.RFC3339, lastUsed)
			t.LastUsedAt = &lu
		}
		for _, sc := range strings.Split(scopesCSV, ",") {
			t.Scopes = append(t.Scopes, Scope(sc))
		}
		candidates = append(candidates, t)
		hashes = append(hashes, keyHash)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range candidates {
		if !verifyTokenKey(key, hashes[i]) {
			continue
		}
		t := &candidates[i]
		if now.UTC().After(t.ExpiresAt) {
			return nil, ErrTokenInvalid
		}
		// last_used_at — не чаще раза в час (п. 14.2): не плодим записи
		// на каждый запрос CI-интеграции.
		if t.LastUsedAt == nil || now.Sub(*t.LastUsedAt) > time.Hour {
			if _, err := s.db.ExecContext(ctx,
				`UPDATE api_tokens SET last_used_at = ? WHERE id = ?`,
				now.UTC().Format(time.RFC3339), t.ID); err != nil {
				return nil, err
			}
			// RFC3339 в БД — секундная точность; держим struct согласованным
			// с round-trip, иначе сравнения «до/после» путаются в наносекундах.
			lu := now.UTC().Truncate(time.Second)
			t.LastUsedAt = &lu
		}
		return t, nil
	}
	return nil, ErrTokenInvalid
}

// RevokeToken — мгновенный отзыв (п. 14.2) с аудитом admin/token_revoke
// той же транзакцией.
func (s *Store) RevokeToken(ctx context.Context, id, actor string, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx,
		`UPDATE api_tokens SET revoked_at = ? WHERE id = ? AND revoked_at = ''`,
		now.UTC().Format(time.RFC3339), id)
	if err != nil {
		return err
	}
	if err := requireAffected(res, id); err != nil {
		return fmt.Errorf("токен %s не найден или уже отозван", id)
	}
	if err := appendAuditTokenEvent(ctx, tx, actor, "token_revoke", "token:"+id, nil, now); err != nil {
		return err
	}
	return tx.Commit()
}

// ListTokens — все токены (без хэшей; zond token list, /settings 5г).
func (s *Store) ListTokens(ctx context.Context) ([]APIToken, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, name, scopes, issued_by, created_at, expires_at, revoked_at, last_used_at
		FROM api_tokens ORDER BY created_at DESC, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []APIToken
	for rows.Next() {
		var t APIToken
		var scopesCSV, created, expires, revoked, lastUsed string
		if err := rows.Scan(&t.ID, &t.Name, &scopesCSV, &t.IssuedBy,
			&created, &expires, &revoked, &lastUsed); err != nil {
			return nil, err
		}
		t.CreatedAt, _ = time.Parse(time.RFC3339, created)
		t.ExpiresAt, _ = time.Parse(time.RFC3339, expires)
		if revoked != "" {
			rt, _ := time.Parse(time.RFC3339, revoked)
			t.RevokedAt = &rt
		}
		if lastUsed != "" {
			lu, _ := time.Parse(time.RFC3339, lastUsed)
			t.LastUsedAt = &lu
		}
		for _, sc := range strings.Split(scopesCSV, ",") {
			t.Scopes = append(t.Scopes, Scope(sc))
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// appendAuditTokenEvent — аудит-событие категории admin внутри транзакции
// выпуска/отзыва токена (п. 14.2: администрирование журналируется).
func appendAuditTokenEvent(ctx context.Context, tx *sql.Tx, actor, action, target string, details map[string]any, now time.Time) error {
	return audit.AppendTx(ctx, tx, []audit.Event{{
		Actor: actor, Category: audit.CatAdmin, Action: action, Target: target,
		Details: details, TS: now,
	}})
}
