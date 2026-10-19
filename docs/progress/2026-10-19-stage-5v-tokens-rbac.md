# Прогресс: этап 5, инкремент 5в (часть 1) — API-токены, RBAC, admin-token fallback

Дата: 2026-10-19
Исполнитель: Coordinator / Stage 5 (инкремент в — SSO/API-токены; часть 1 из 2)
Статус: **done (часть 1); часть 2 (SAML SP, 5в-5) — следующий шаг**

## 1. Цель

Закрыть программный доступ и авторизацию REST API (blueprint п. 11.2,
п. 11.3, п. 14.2, ADR-0011): API-токены со scope для CI/интеграций,
RBAC-матрица admin/viewer, аварийный admin-token fallback, аудит
аутентификации/авторизации. SAML-флоу (login/ACS/SLO/JIT) — часть 2 (5в-5);
интерфейсы под него (SessionStore, actor `sso:<subject>`) уже зафиксированы
и покрыты тестами.

Инкремент разбит на мелкие шаги (по запросу): 5в-1 → 5в-4 ниже, каждый —
отдельный коммит.

## 2. Что сделано (по шагам)

| Шаг | Содержание | Коммит |
|---|---|---|
| 5в-1 | Миграция `0006_users_api_tokens.sql` (`users` с CHECK ролей, `api_tokens` с UNIQUE key_hash); store: `UpsertUser` (JIT + обновление роли при каждом входе), `IssueToken` (argon2id-хэш, TTL default 90д, аудит admin/token_issue той же транзакцией), `ResolveToken` (constant-time сверка по неотозванным, отзыв мгновенный, `last_used_at` троттлинг 1ч), `RevokeToken` (+аудит), `ListTokens`; 7 тестов | `279b001` |
| 5в-2 | Пакет `internal/auth` (заменил заглушку): `Role` admin/viewer, `MaxRole` (admin+viewer→admin, п. 11.3), RBAC-матрица действий (view/export/review/scan/audit), `Subject` в ctx, in-memory `SessionStore` (TTL 12ч, ленивое истечение, Delete для logout); 5 тестов | `e1d86e6` |
| 5в-3 | CLI `zond token issue\|list\|revoke` (ключ показывается один раз, `-scopes`, `-ttl` default 2160h); auth-middleware API: цепочка SSO-сессия→Bearer→admin-token, невалидный Bearer не проваливается в fallback; scope→action маппинг; 401/403 с аудитом `auth/api_auth_failure` и `authorization/forbidden` | `f251301` (объединён с 5в-4) |
| 5в-4 | Admin-token fallback: `X-Admin-Token` из env `CLASSIFIER_ADMIN_TOKEN` при `admin_token_fallback: true`, каждое использование — аудит `auth/admin_token_used` (warn); actor propagation из ctx в ревью/экспорт/стоп/старт скана (`ScanRunner.Start` принимает actor — аудит движка от имени инициатора); health/ready вне аутентификации; `zond serve` wiring (`sso.enabled` из connections.yaml); 8 тестов API | `f251301` |

## 3. Ключевые решения

См. `docs/decisions/ADR-impl-stage-5v-tokens-rbac.md` (D1–D8). Кратко:
argon2id-хэш ключей (x/crypto промоутнут в direct — новых внешних зависимостей
нет); resolve перебором неотозванных (токенов мало, отзыв мгновенный);
невалидный Bearer ≠ fallback в admin-token; роли для людей / scope для машин;
actor из ctx, без глобального состояния; режим `sso.enabled: false` —
прозрачный 5б (обратная совместимость).

## 4. Проверки (протокол — docs/validation/2026-10-19-stage-5v-tokens-rbac.md)

- `go build`, `go vet`, `gofmt` — чисто; `go test ./...` — все пакеты ok.
- Live-smoke: `zond token issue` (ключ один раз) → `serve` с
  `sso.enabled: true`: без креденшелов 401, с Bearer 200, health открыт;
  `token revoke` → тот же ключ 401 (мгновенно); admin-token fallback 200.

## 5. Изменённые файлы

`internal/verdict/store/migrations/0006_users_api_tokens.sql`,
`internal/verdict/store/{tokens.go,tokens_test.go}`, `internal/auth/{auth.go,
auth_test.go}` (doc.go-заглушка удалена), `internal/api/{auth.go,auth_test.go}`,
`internal/api/{server,handlers_scans,handlers_verdicts}.go` (withAuth,
requireAction, actorFromCtx), `cmd/zond/main.go` (token CLI, serve auth
wiring, runner actor), `go.mod` (x/crypto → direct).

## 6. Не вошло (часть 2 — 5в-5, и далее)

- **SAML SP (crewjam/saml)**: `/saml/metadata`, SP-initiated login, ACS
  (POST binding), SLO; IdP-метаданные из `idp_metadata_url`/`_file` +
  refresh 24ч; JIT-прvisioning в `users`; маппинг ролей из
  `role_attribute`/групп (MaxRole); аудит login success/failure/logout/SLO;
  Keycloak в `deploy/` + testcontainers-флоу (п. 16.5). Интерфейсы готовы:
  `SessionStore.Create`, cookie `zond_session`, actor `sso:<subject>`.
- Rate-limit 100 req/s на субъекта (п. 11.2) — субъекты появились, лимит
  логично вводить вместе с SAML (5в-5/5г) как отдельный middleware.
- Веб-UI (5г): страница `/audit` (admin-only маршрут ActionAudit уже в
  RBAC), `/settings` с пользователями/токенами.

## 7. Следующие шаги

1. **5в-5**: SAML SP + JIT + аудит входов + Keycloak compose (DoD SSO).
2. 5г: веб-UI п. 11.3 поверх API + scheduler (retention, async-экспорт).
