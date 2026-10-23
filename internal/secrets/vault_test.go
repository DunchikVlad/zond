// Тесты Vault-резолвера (ADR-0012, п. 12.1): kv-v2, dynamic leases,
// кэш лиз (R11), фоновое продление/отзыв, аудит без значений,
// аутентификация (token/kubernetes). Внешний мир не трогается — fake
// Vault на httptest.
package secrets

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DunchikVlad/zond/internal/config"
)

// fakeVault — httptest-стенд Vault: kv-v2 (kv/data/zond/mongo-prod),
// dynamic (database/creds/ch-prod), продление (sys/renew/<id>).
// Поведение продления переключается полями renewStatus/renewBody.
type fakeVault struct {
	*httptest.Server

	mu         sync.Mutex
	reads      map[string]int // path → число чтений
	renewCalls atomic.Int32
	renewCode  int    // 0 → успех; иначе код ответа на продление
	renewLease string // lease_id в ответе продления (пусто — тот же)
}

func newFakeVault(t *testing.T) *fakeVault {
	t.Helper()
	fv := &fakeVault{reads: map[string]int{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/kv/data/zond/mongo-prod", func(w http.ResponseWriter, r *http.Request) {
		fv.count("/v1/kv/data/zond/mongo-prod")
		writeJSON(w, map[string]any{
			"data": map[string]any{
				"data":     map[string]any{"uri": "mongodb://vault-user:vault-pass@127.0.0.1:27017/db"},
				"metadata": map[string]any{"version": 3},
			},
		})
	})
	mux.HandleFunc("/v1/database/creds/ch-prod", func(w http.ResponseWriter, r *http.Request) {
		fv.count("/v1/database/creds/ch-prod")
		writeJSON(w, map[string]any{
			"lease_id":       "lease-ch-1",
			"renewable":      true,
			"lease_duration": 2, // секунды; продление на ~1 с (для тестов)
			"data":           map[string]any{"username": "ro-user", "password": "ro-pass"},
		})
	})
	mux.HandleFunc("/v1/sys/renew/", func(w http.ResponseWriter, r *http.Request) {
		fv.renewCalls.Add(1)
		fv.mu.Lock()
		code, lease := fv.renewCode, fv.renewLease
		fv.mu.Unlock()
		if code != 0 {
			w.WriteHeader(code)
			writeJSON(w, map[string]any{"errors": []string{"renew denied"}})
			return
		}
		if lease == "" {
			lease = "lease-ch-1"
		}
		writeJSON(w, map[string]any{"lease_id": lease, "renewable": true, "lease_duration": 120})
	})
	mux.HandleFunc("/v1/auth/kubernetes/login", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["role"] != "zond" || body["jwt"] != "k8s-jwt-token" {
			w.WriteHeader(403)
			writeJSON(w, map[string]any{"errors": []string{"login denied"}})
			return
		}
		writeJSON(w, map[string]any{"auth": map[string]any{"client_token": "k8s-client-token"}})
	})
	fv.Server = httptest.NewServer(mux)
	t.Cleanup(fv.Server.Close)
	return fv
}

func (fv *fakeVault) count(path string) {
	fv.mu.Lock()
	fv.reads[path]++
	fv.mu.Unlock()
}

func (fv *fakeVault) readsOf(path string) int {
	fv.mu.Lock()
	defer fv.mu.Unlock()
	return fv.reads[path]
}

func (fv *fakeVault) setRenew(code int, lease string) {
	fv.mu.Lock()
	fv.renewCode, fv.renewLease = code, lease
	fv.mu.Unlock()
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// testResolver — резолвер поверх стенда: ch-prod (dynamic), mongo-prod (kv-v2).
func testResolver(t *testing.T, fv *fakeVault, hook AuditHook, now func() time.Time) *Vault {
	t.Helper()
	v, err := NewVault(Config{
		Address: fv.URL,
		Token:   "dev-token",
		Secrets: map[string]Entry{
			"mongo-prod": {Path: "kv/data/zond/mongo-prod", Key: "uri"},
			"ch-prod":    {Path: "database/creds/ch-prod", DSNTemplate: "clickhouse://{{username}}:{{password}}@ch-host:9000/analytics"},
		},
		Audit: hook,
		Now:   now,
	})
	if err != nil {
		t.Fatalf("NewVault: %v", err)
	}
	t.Cleanup(func() { _ = v.Close() })
	return v
}

func realNow() func() time.Time { return time.Now }

func TestResolveKV2(t *testing.T) {
	fv := newFakeVault(t)
	v := testResolver(t, fv, nil, realNow())
	got, err := v.Resolve(context.Background(), "mongo-prod")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != "mongodb://vault-user:vault-pass@127.0.0.1:27017/db" {
		t.Errorf("kv-v2 uri: %q", got)
	}
	// kv-v2 дочитывается на каждый коннект (ротация на стороне Vault).
	if _, err := v.Resolve(context.Background(), "mongo-prod"); err != nil {
		t.Fatalf("Resolve 2: %v", err)
	}
	if n := fv.readsOf("/v1/kv/data/zond/mongo-prod"); n != 2 {
		t.Errorf("kv-v2 прочитан %d раз, ожидалось 2 (без кэша)", n)
	}
}

func TestResolveDynamicTemplate(t *testing.T) {
	fv := newFakeVault(t)
	v := testResolver(t, fv, nil, realNow())
	got, err := v.Resolve(context.Background(), "ch-prod")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	want := "clickhouse://ro-user:ro-pass@ch-host:9000/analytics"
	if got != want {
		t.Errorf("dynamic dsn: %q, want %q", got, want)
	}
}

func TestResolveDynamicCacheWhileLeaseValid(t *testing.T) {
	fv := newFakeVault(t)
	now := time.Now()
	v := testResolver(t, fv, nil, func() time.Time { return now })
	if _, err := v.Resolve(context.Background(), "ch-prod"); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	// До истечения лизы — кэш: сеть не трогаем (R11).
	for i := 0; i < 3; i++ {
		now = now.Add(500 * time.Millisecond)
		if _, err := v.Resolve(context.Background(), "ch-prod"); err != nil {
			t.Fatalf("Resolve %d: %v", i, err)
		}
	}
	if n := fv.readsOf("/v1/database/creds/ch-prod"); n != 1 {
		t.Errorf("dynamic прочитан %d раз, ожидался кэш (1)", n)
	}
	// Лиза истекла — прозрачный перезапрос нового секрета.
	now = now.Add(2 * time.Second)
	if _, err := v.Resolve(context.Background(), "ch-prod"); err != nil {
		t.Fatalf("Resolve после истечения: %v", err)
	}
	if n := fv.readsOf("/v1/database/creds/ch-prod"); n != 2 {
		t.Errorf("после истечения прочитан %d раз, ожидалось 2", n)
	}
}

func TestResolveUnavailable(t *testing.T) {
	fv := newFakeVault(t)
	v := testResolver(t, fv, nil, realNow())
	// Стенд «падает»: кэша нет → ErrUnavailable (источник → vault_unavailable).
	fv.Server.Close()
	_, err := v.Resolve(context.Background(), "ch-prod")
	if !errors.Is(err, ErrUnavailable) {
		t.Errorf("ожидался ErrUnavailable, got %v", err)
	}
	_, err = v.Resolve(context.Background(), "mongo-prod")
	if !errors.Is(err, ErrUnavailable) {
		t.Errorf("kv-v2: ожидался ErrUnavailable, got %v", err)
	}
}

func TestResolveUnknownRef(t *testing.T) {
	fv := newFakeVault(t)
	v := testResolver(t, fv, nil, realNow())
	if _, err := v.Resolve(context.Background(), "nope"); err == nil || errors.Is(err, ErrUnavailable) {
		t.Errorf("неизвестный ref: %v", err)
	}
}

// TestRenewal — фоновое продление: лиза 2 с → renew ~через 1 с, кэш
// продлевается; аудит получает lease_renew без значений.
func TestRenewal(t *testing.T) {
	fv := newFakeVault(t)
	var mu sync.Mutex
	var actions []string
	v := testResolver(t, fv, func(_ context.Context, ref, path, action string) {
		mu.Lock()
		actions = append(actions, ref+"|"+path+"|"+action)
		mu.Unlock()
	}, realNow())
	if _, err := v.Resolve(context.Background(), "ch-prod"); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for fv.renewCalls.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if fv.renewCalls.Load() == 0 {
		t.Fatal("продление не вызвано за 5 с")
	}
	mu.Lock()
	defer mu.Unlock()
	found := false
	for _, a := range actions {
		if strings.Contains(a, "lease_renew") {
			found = true
		}
		if strings.Contains(a, "ro-pass") || strings.Contains(a, "ro-user") {
			t.Errorf("аудит содержит значение секрета: %q", a)
		}
	}
	if !found {
		t.Errorf("нет lease_renew в аудите: %v", actions)
	}
}

// TestRenewRevoked — 403 на продление: кэш сброшен сразу, следующий
// Resolve читает новый секрет (прозрачный реконнект).
func TestRenewRevoked(t *testing.T) {
	fv := newFakeVault(t)
	fv.setRenew(403, "")
	var mu sync.Mutex
	var actions []string
	v := testResolver(t, fv, func(_ context.Context, ref, path, action string) {
		mu.Lock()
		actions = append(actions, action)
		mu.Unlock()
	}, realNow())
	if _, err := v.Resolve(context.Background(), "ch-prod"); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for fv.renewCalls.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if fv.renewCalls.Load() == 0 {
		t.Fatal("продление не вызвано за 5 с")
	}
	mu.Lock()
	hasRevoked := false
	for _, a := range actions {
		if a == ActionRevoked {
			hasRevoked = true
		}
	}
	mu.Unlock()
	if !hasRevoked {
		t.Fatalf("ожидался lease_revoked, аудит: %v", actions)
	}
	// Кэш сброшен → Resolve читает заново.
	if _, err := v.Resolve(context.Background(), "ch-prod"); err != nil {
		t.Fatalf("Resolve после отзыва: %v", err)
	}
	if n := fv.readsOf("/v1/database/creds/ch-prod"); n != 2 {
		t.Errorf("после отзыва прочитан %d раз, ожидалось 2", n)
	}
}

// TestRenewTransientFailureKeepsCache — сбой продления (500) не убивает
// валидный кэш: до истечения лизы Resolve обслуживается из памяти.
func TestRenewTransientFailureKeepsCache(t *testing.T) {
	fv := newFakeVault(t)
	fv.setRenew(500, "")
	now := time.Now()
	v := testResolver(t, fv, nil, func() time.Time { return now })
	if _, err := v.Resolve(context.Background(), "ch-prod"); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for fv.renewCalls.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	// Кэш жив до истечения (истечение подвигаем только за пределы now).
	now = now.Add(1500 * time.Millisecond)
	if _, err := v.Resolve(context.Background(), "ch-prod"); err != nil {
		t.Fatalf("Resolve до истечения: %v", err)
	}
	if n := fv.readsOf("/v1/database/creds/ch-prod"); n != 1 {
		t.Errorf("кэш должен жить до истечения: прочитан %d раз", n)
	}
}

func TestAuditResolveHasNoValues(t *testing.T) {
	fv := newFakeVault(t)
	var mu sync.Mutex
	var got []string
	v := testResolver(t, fv, func(_ context.Context, ref, path, action string) {
		mu.Lock()
		got = append(got, fmt.Sprintf("%s|%s|%s", ref, path, action))
		mu.Unlock()
	}, realNow())
	if _, err := v.Resolve(context.Background(), "mongo-prod"); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 || got[0] != "mongo-prod|kv/data/zond/mongo-prod|resolve" {
		t.Errorf("аудит resolve: %v", got)
	}
}

func TestCloseIdempotent(t *testing.T) {
	fv := newFakeVault(t)
	v := testResolver(t, fv, nil, realNow())
	if _, err := v.Resolve(context.Background(), "ch-prod"); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if err := v.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := v.Close(); err != nil {
		t.Fatalf("Close 2: %v", err)
	}
}

func TestAuthenticateToken(t *testing.T) {
	t.Setenv("ZOND_TEST_VAULT_TOKEN", "tok-123")
	got, err := Authenticate(context.Background(), "http://127.0.0.1:1", 0, Auth{Method: "token", TokenEnv: "ZOND_TEST_VAULT_TOKEN"})
	if err != nil || got != "tok-123" {
		t.Errorf("token auth: %q %v", got, err)
	}
	if _, err := Authenticate(context.Background(), "http://127.0.0.1:1", 0, Auth{Method: "token", TokenEnv: "ZOND_TEST_VAULT_MISSING"}); err == nil {
		t.Error("пустой env: ожидалась ошибка")
	}
	if _, err := Authenticate(context.Background(), "http://127.0.0.1:1", 0, Auth{Method: "nope"}); err == nil {
		t.Error("неизвестный method: ожидалась ошибка")
	}
}

func TestAuthenticateKubernetes(t *testing.T) {
	fv := newFakeVault(t)
	jwtFile := filepath.Join(t.TempDir(), "jwt")
	if err := os.WriteFile(jwtFile, []byte("k8s-jwt-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := Authenticate(context.Background(), fv.URL, time.Second, Auth{Method: "kubernetes", Role: "zond", JWTFile: jwtFile})
	if err != nil || got != "k8s-client-token" {
		t.Errorf("kubernetes login: %q %v", got, err)
	}
	// Отказ стенда → ошибка (fail-fast).
	if err := os.WriteFile(jwtFile, []byte("wrong"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Authenticate(context.Background(), fv.URL, time.Second, Auth{Method: "kubernetes", Role: "zond", JWTFile: jwtFile}); err == nil {
		t.Error("невалидный JWT: ожидалась ошибка логина")
	}
	if _, err := Authenticate(context.Background(), fv.URL, time.Second, Auth{Method: "kubernetes", Role: "zond", JWTFile: filepath.Join(t.TempDir(), "missing")}); err == nil {
		t.Error("отсутствующий JWT-файл: ожидалась ошибка")
	}
}

func TestNewFromConfig(t *testing.T) {
	t.Setenv("ZOND_TEST_VAULT_TOKEN", "tok-123")
	fv := newFakeVault(t)
	r, err := NewFromConfig(context.Background(), config.Vault{
		Enabled: true,
		Address: fv.URL,
		Auth:    config.VaultAuth{Method: "token", TokenEnv: "ZOND_TEST_VAULT_TOKEN"},
		Secrets: []config.VaultSecret{
			{Ref: "mongo-prod", Path: "kv/data/zond/mongo-prod", Key: "uri"},
		},
	}, nil)
	if err != nil {
		t.Fatalf("NewFromConfig: %v", err)
	}
	defer r.Close()
	got, err := r.Resolve(context.Background(), "mongo-prod")
	if err != nil || got != "mongodb://vault-user:vault-pass@127.0.0.1:27017/db" {
		t.Errorf("Resolve: %q %v", got, err)
	}
	if _, err := NewFromConfig(context.Background(), config.Vault{}, nil); err == nil {
		t.Error("disabled: ожидалась ошибка")
	}
}
