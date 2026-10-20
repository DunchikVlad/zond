# Валидация: этап 5, инкремент 5в-5 — SAML SP (SSO)

Дата: 2026-10-20
Объект: инкремент 5в-5 (ADR-0011, blueprint п. 11.3), см.
`docs/progress/2026-10-20-stage-5v-saml-sp.md`

## 1. Что проверялось и как

| Проверка | Команда | Результат |
|---|---|---|
| Сборка | `go build ./...` | чисто |
| Vet | `go vet ./...` | чисто |
| Форматирование | `gofmt -l .` | пусто |
| Unit + E2E (кроме Keycloak) | `go test ./...` | все пакеты ok |
| Race | `go test -race ./internal/...` | ok |
| Линт | `golangci-lint run` | 0 issues (depguard расширен под internal/auth — SAML) |
| Конфиг | `make config-check` | OK |
| Smoke fail-fast | `serve` + `sso.enabled: true`, IdP `idp.example.com` недоступен | exit 2: «метаданные IdP: lookup … no such host» |
| Smoke без SSO | `serve` (sso.enabled=false) | `/api/health` 200, `/api/v1/scans` 200 |
| E2E Keycloak | `go test -run TestSSOAgainstKeycloak` | **SKIP локально** (docker не запущен на машине разработки) — testcontainers-skip по паттерну conftest; предназначен для CI |

## 2. Что подтверждено unit-тестами (internal/auth)

- `TestNewSPBuildsWithEphemeralCert` — SP строится с ephemeral-сертификатом,
  событие `sso_ephemeral_cert` в аудите.
- `TestNewSPFailsOnBadACS` — acs_url без суффикса `/saml/acs` / невалиден →
  ошибка конструктора (fail-fast до serve).
- `TestSessionProviderCreateSession` — JIT (subject/display/role), сессия в
  store, cookie `zond_session` (HttpOnly, Lax, Path=/), аудит
  `sso_login_success` последним событием.
- `TestMapRole` — роль из `Role` (admin/viewer/максимум из нескольких),
  группы путём (`/zond/admins`→admin, `cn=… viewers`→viewer), без ролей →
  viewer, чужие значения игнорируются.
- `TestLogoutEndsSession` — сессия удалена, cookie инвалидирован, 302 на IdP
  с `SAMLRequest` (подписанный LogoutRequest).
- `TestSLOIdPInitiatedDeletesBySubject` — LogoutRequest (POST) завершает все
  сессии субъекта, чужие не тронуты.
- `TestHandlerRoutes` — metadata отдаётся, `/saml/login` анонима → 302 на IdP.
- `TestSamlErrReasonNoResponseLeak` — причина ошибки без XML ответа.

## 3. Что подтверждает E2E (TestSSOAgainstKeycloak, в CI)

Keycloak 25.0.6 (testcontainers, realm-zond.json): SP-initiated флоу
программным HTTP-клиентом (форма входа → auto-post ACS) → cookie сессии →
`GET /api/v1/scans` 200; JIT `admin` (роль admin) и `viewer` (роль viewer) в
`users`; viewer на `POST /api/v1/scans` → 403 (RBAC п. 11.3); два события
`sso_login_success` с акторами `sso:admin`/`sso:viewer`; hash-chain аудита
сходится. Подпись assertion валидируется crewjam по ключам realm (Keycloak
подписывает по умолчанию).

## 4. Не проверено / ограничения

- **E2E не выполнен локально** (нет docker на машине разработки) — первый
  прогон будет в CI; типовые риски: wildcard redirect URI у Keycloak-клиента
  (в realm допущен `http://127.0.0.1:*`), формат NameID (в тесте —
  username по умолчанию Keycloak). Падение в CI разбирается по логу.
- Браузерное поведение SameSite=Lax на http-dev не проверялось (Chrome/Firefox
  могут не доставить tracked-request cookie на POST ACS) — зафиксировано,
  mitigations: `cookie_samesite: none` + https в prod.
- Нагрузочное: SessionStore/SP не нагружались (сессий мало по построению).
- Подпись IdP-initiated LogoutRequest не валидируется (см. security note) —
  корректность обработки SLO подтверждена unit-тестом разбора, не криптографией.

## 5. Остаточные риски

- Ephemeral-сертификат в prod-конфиге заметен только warn-аудитом —
  `doctor` (этап 7) должен проверять наличие sp_certificate_file.
- Refresh метаданных раз в сутки: компрометация/ротация ключей IdP между
  циклами — окно до 24 ч (п. 11.3 допускает; ручной рестарт serve сокращает).
