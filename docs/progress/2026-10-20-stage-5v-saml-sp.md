# Прогресс: этап 5, инкремент 5в (часть 2) — SAML SP (5в-5, ADR-0011)

Дата: 2026-10-20
Исполнитель: Coordinator / Stage 5 (инкремент в, часть 2 — SAML Service Provider)
Статус: **done (часть 2)** — SSO-контур этапа 5 закрыт: SAML login/ACS/SLO,
JIT, роли из assertion, аудит входов, Keycloak-стенд. Часть 1 (API-токены,
RBAC) — `2026-10-19-stage-5v-tokens-rbac.md`.

## 1. Цель

Завершить SSO SAML 2.0 (blueprint п. 11.3, ADR-0011, DoD MVP): встроенный
Service Provider на crewjam/saml, SP-initiated login, ACS (POST binding,
подпись assertion, InResponseTo), SP- и IdP-initiated SLO, JIT-прvisioning в
`users` с ролями из SAML-атрибута/групп, аудит auth-событий, Keycloak-стенд
(п. 16.5). Интерфейсы части 1 (SessionStore, actor `sso:<subject>`)
использованы как есть.

## 2. Что сделано

| Чанк | Результат |
|---|---|
| 5в-5а | Пакет `internal/auth/saml.go`: `SP` поверх `samlsp.Middleware` с нашим `SessionProvider` (cookie `zond_session`, мост в `SessionStore`); ключ/сертификат подписи SP из `sp_key_file`/`sp_certificate_file` либо ephemeral self-signed (dev, warn+аудит); роль из атрибута `role_attribute` и групп (`groups`/`memberOf`, токены admin/viewer(s)), `MaxRole`, default viewer; JIT через hook `UpsertUser` |
| 5в-5б | Эндпоинты: `GET /saml/metadata`, `GET /saml/login` (SP-initiated), `POST /saml/acs` (crewjam: подпись, хронология, InResponseTo через tracked-request cookie; ошибки ACS — аудит `sso_login_failure` без SAMLResponse, только причина ≤160 символов), `GET /saml/logout` (локальный + подписанный LogoutRequest redirect'ом на IdP), `GET|POST /saml/slo` (IdP-initiated: NameID из LogoutRequest → `DeleteBySubject`; crewjam парсер не поставляет — минимальный XML-разбор redirect base64+flate/POST base64) |
| 5в-5в | Метаданные IdP: загрузка при старте serve (fail-fast при недоступности, п. 11.3) из `idp_metadata_url`/`_file` (`auth.FetchMetadata`); refresh каждые 24 ч — пересборка middleware и атомарная замена (`atomic.Pointer`), ошибка — warn+аудит, прежняя версия действует |
| 5в-5г | Wiring: `zond serve` строит SP при `sso.enabled: true` и монтирует через `api.WithSAML`; `/saml/*` исключены из auth-middleware (точки входа анонимны по построению протокола); конфиг SSO расширен (`sp_certificate_file`, `sp_key_file`, `cookie_samesite lax|none`); актёр аудита из SP (`sso:<subject>`, `sso:unknown`, `saml`) |
| 5в-5д | Keycloak-стенд: `deploy/keycloak/realm-zond.json` (realm zond, клиент zond SAML с маппером ролей в атрибут `Role`, пользователи admin/admin123→admin, viewer/viewer123→viewer) + `deploy/docker-compose.keycloak.yml` |
| 5в-5е | Тесты: unit — построение SP, sessionProvider (JIT/cookie/аудит), mapRole (роли/группы/максимум/default), logout (сессия+cookie+redirect на IdP с SAMLRequest), IdP-initiated SLO (DeleteBySubject не трогает чужие), маршруты (metadata, login→302), безопасная причина ошибок; E2E — `TestSSOAgainstKeycloak`: testcontainers Keycloak 25.0.6, программный браузерный флоу (login-форма → auto-post ACS), API от имени `sso:admin`/`sso:viewer` (RBAC 200/403), JIT-записи, аудит входов, hash-chain — skip без docker |

## 3. Ключевые решения

См. `docs/decisions/ADR-impl-stage-5v-saml.md` (D1–D6). Кратко:

- **Ключи SP — файлы в конфиге, ephemeral как bootstrap.** П. 11.3: файл в
  конфигурации, ротация «добавить → раскатать → убрать»; ephemeral —
  только dev/демо, с warn-аудитом.
- **Refresh метаданных = пересборка middleware.** crewjam не даёт
  hot-swap IDPMetadata; middleware лёгкий, замена атомарна.
- **SAMLResponse в аудит/ошибки не попадает** — только типизированная
  причина (PrivateErr, ≤160 символов). ADR-0010.
- **`cookie_samesite` в конфиге.** Lax (default) на http-dev: часть браузеров
  не пошлёт tracked-request cookie на POST ACS — задокументировано; prod —
  https + none (Secure).
- **Аудит SSO best-effort.** П. 14.2 требует записи, но отказ входа из-за
  аудита = self-DoS; ошибки аудита идут в лог, цепочку ловит verify.
- **IdP-initiated SLO — свой минимальный разбор LogoutRequest** (NameID);
  подпись LogoutRequest от IdP не валидируется (crewjam не поставляет
  валидатор; риск зафиксирован, см. security note).
- **Развёртывание без path-префикса** — маршруты фиксированы `/saml/*`;
  acs_url обязан оканчиваться на `/saml/acs` (валидация на старте).

## 4. Проверки (протокол — docs/validation/2026-10-20-stage-5v-saml.md)

- `go build`, `go vet`, `gofmt` — чисто; `golangci-lint` — 0 issues
  (depguard расширен: net/http разрешён в internal/auth — SAML не вызывает LLM).
- `go test ./...`, `go test -race ./internal/...` — все пакеты ok.
- `make config-check` — OK.
- Smoke: `serve` с `sso.enabled: true` и недоступным IdP → fail-fast
  (exit 2, причина); `serve` без SSO → health 200, `/api/v1/scans` 200.
- E2E Keycloak — skip локально (docker не запущен на машине разработки),
  предназначен для CI (паттерн conftest).

## 5. Изменённые файлы

Новые: `internal/auth/saml.go`, `internal/auth/saml_test.go`,
`internal/auth/saml_keycloak_test.go`, `deploy/keycloak/realm-zond.json`,
`deploy/docker-compose.keycloak.yml`. Изменённые: `internal/auth/auth.go`
(`DeleteBySubject`), `internal/api/server.go` (`WithSAML`, маршруты),
`internal/api/auth.go` (пропуск /saml/*), `internal/config/config.go`
(SSO-поля + валидация), `configs/connections.yaml`, `cmd/zond/main.go`
(serve: SP, refresh-горутина), `.golangci.yml` (depguard),
`go.mod/go.sum` (crewjam/saml v0.5.1 и транзитивы), `internal/verdict/store/verdicts.go` (QF1003).

## 6. Не вошло

- Rate-limit 100 req/s (п. 11.2) — субъекты есть; отдельный middleware,
  разумно вместе с веб-UI (5г).
- Веб-UI (5г): защита страниц `/saml/login`-редиректами, страницы п. 11.3,
  `/audit`, scheduler (retention, async-экспорт).
- `zond doctor`: проверка доступности IdP metadata + agent-check уже есть
  (этап 7).
- Проверка подписи IdP-initiated LogoutRequest (см. security note).
- ACS по Redirect-binding (только POST — по умолчанию crewjam и blueprint).

## 7. Следующие шаги

1. Инкремент 5г: веб-UI (п. 11.3) поверх API + SSO-сессий, `/audit`,
   scheduler (cron-пересканы, retention аудита/кэша п. 15.4, async-экспорт).
2. Этап 6 (eval-harness), этап 7 (харденинг: doctor, Vault-резолвер,
   backup/restore, подпись релиза).
