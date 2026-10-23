// Адаптер от конфигурации (internal/config, ADR-0012) и аутентификация
// в Vault: token из env (dev/демо) или kubernetes-логин по JWT
// сервис-аккаунта (prod). Токен в конфиге запрещён (п. 12.1) — строгий
// парсинг config отвергнет лишний ключ.
package secrets

import (
	"context"
	"fmt"
	"os"
	"time"

	vaultapi "github.com/hashicorp/vault/api"

	"github.com/DunchikVlad/zond/internal/config"
)

// defaultK8sJWTFile — стандартный путь токена сервис-аккаунта (п. 12.1).
const defaultK8sJWTFile = "/var/run/secrets/kubernetes.io/serviceaccount/token"

// k8sLoginPath — эндпоинт kubernetes-аутентификации (mount auth/kubernetes).
const k8sLoginPath = "auth/kubernetes/login"

// Auth — параметры аутентификации из конфигурации vault.auth.
type Auth struct {
	Method   string // token | kubernetes
	TokenEnv string // method=token: имя env-переменной с токеном
	Role     string // method=kubernetes: роль Vault
	JWTFile  string // method=kubernetes: путь к JWT (пусто — стандартный путь SA)
}

// Authenticate — клиентский токен Vault по Auth. method=token: чтение env
// (fail-fast при пустом); method=kubernetes: чтение JWT файла и логин
// POST auth/kubernetes/login. Единая точка для cmd и doctor.
func Authenticate(ctx context.Context, address string, timeout time.Duration, a Auth) (string, error) {
	switch a.Method {
	case "token":
		if a.TokenEnv == "" {
			return "", fmt.Errorf("secrets: auth.token_env не задан")
		}
		tok := os.Getenv(a.TokenEnv)
		if tok == "" {
			return "", fmt.Errorf("secrets: env %s не задан (vault auth method=token)", a.TokenEnv)
		}
		return tok, nil
	case "kubernetes":
		if a.Role == "" {
			return "", fmt.Errorf("secrets: auth.role не задан (vault auth method=kubernetes)")
		}
		jwtFile := a.JWTFile
		if jwtFile == "" {
			jwtFile = defaultK8sJWTFile
		}
		jwt, err := os.ReadFile(jwtFile)
		if err != nil {
			return "", fmt.Errorf("secrets: чтение JWT %s: %w", jwtFile, err)
		}
		client, err := newClient(address, timeout)
		if err != nil {
			return "", err
		}
		resp, err := client.Logical().WriteWithContext(ctx, k8sLoginPath, map[string]any{
			"role": a.Role, "jwt": string(jwt),
		})
		if err != nil {
			return "", fmt.Errorf("secrets: kubernetes login (роль %q): %w", a.Role, err)
		}
		if resp == nil || resp.Auth == nil || resp.Auth.ClientToken == "" {
			return "", fmt.Errorf("secrets: kubernetes login (роль %q): пустой ответ без client_token", a.Role)
		}
		return resp.Auth.ClientToken, nil
	default:
		return "", fmt.Errorf("secrets: vault auth method %q не поддержан (token|kubernetes)", a.Method)
	}
}

// NewFromConfig — резолвер по блоку connections.yaml (единая точка для
// cmd и doctor): аутентификация → NewVault. Ошибки — fail-fast
// (blueprint п. 12.1, ADR-0009).
func NewFromConfig(ctx context.Context, v config.Vault, hook AuditHook) (Resolver, error) {
	if !v.Enabled {
		return nil, fmt.Errorf("secrets: vault не включён (enabled=false)")
	}
	auth := Auth{
		Method: v.Auth.Method, TokenEnv: v.Auth.TokenEnv,
		Role: v.Auth.Role, JWTFile: v.Auth.JWTFile,
	}
	tok, err := Authenticate(ctx, v.Address, 0, auth)
	if err != nil {
		return nil, err
	}
	entries := make(map[string]Entry, len(v.Secrets))
	for _, s := range v.Secrets {
		entries[s.Ref] = Entry{Path: s.Path, Key: s.Key, DSNTemplate: s.DSNTemplate}
	}
	return NewVault(Config{Address: v.Address, Token: tok, Secrets: entries, Audit: hook})
}

// newClient — vault/api клиент без токена (Authenticate, NewVault).
func newClient(address string, timeout time.Duration) (*vaultapi.Client, error) {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	cfg := vaultapi.DefaultConfig()
	cfg.Address = address
	client, err := vaultapi.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("secrets: клиент Vault: %w", err)
	}
	client.SetClientTimeout(timeout)
	client.SetMaxRetries(0) // fail-fast: без библиотечных ретраев (как webhook, S6в)
	return client, nil
}
