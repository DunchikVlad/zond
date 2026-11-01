# S9-8: фиксы замечаний стенда (З1 ClickHouse INFORMATION_SCHEMA, З2 admin-token при выключенном SSO)

Дата: 2026-11-01
Основание: замечания З1/З2 протокола `docs/validation/2026-11-01-stand-deployment.md`
(валидация нового стенда Debian 13). Коммит одного инкремента: код + тесты.

## З1: ClickHouse 26.x — сканировались системные view `INFORMATION_SCHEMA`

- Причина: фильтр `ListTables` (`internal/connector/clickhouse/connector.go`)
  исключал базы `('system','information_schema')` регистрозависимо, а CH 26.x
  создаёт копии системных view в базе `INFORMATION_SCHEMA` (uppercase, 20 шт).
  Итог на стенде: 21 таблица вместо 1, 489 вердиктов (64 ложных
  `PERSON_NAME` PII auto_accepted, 423 `UNKNOWN` в очереди ревью).
- Фикс: сравнение через `lower(database)` — закрывает любые регистровые
  варианты системных баз (п. 9: исключаем системные схемы).
- Проверка живьём: повторный скан ch-test на стенде — 1 таблица
  (`default.customers`), 5 вердиктов (см. обновление validation-документа).

## З2: при `sso.enabled: false` аутентификация отключалась полностью

- Причина: API (`withAuth`, `requireAction`) и web (`withAuth`) при
  выключенном SSO пропускали всё без проверок; web подставлял субъекта
  dev/admin. Противоречие blueprint п. 12 («режим без SSO — только
  admin-токен»); побочно — не действовал rate-limit субъектов (S9-6).
- Решение (fail-closed, п. 14):
  - **API**: auth-middleware и RBAC активны, когда задан admin-token, даже
    при `sso.enabled=false`; цепочка субъектов та же (сессия → Bearer →
    X-Admin-Token). Совсем без auth — только dev (оба поля пустые).
  - **Web**: режим token-only: страницы требуют сессию (GET → 302 /login,
    POST → 403); новые `GET/POST /login` — форма ввода admin-token,
    constant-time сравнение, выдача сессии (zond_session, admin),
    brute-force блокировка по IP общим `auth.AttemptLimiter` (5 неудач /
    10 мин → блок 15 мин, п. 14), аудит `admin_token_used` (warn) и
    `login_failure` (п. 14.2). /login и /static/ доступны анонимно.
  - **serve**: при выключенном SSO и пустом `CLASSIFIER_ADMIN_TOKEN` —
    fail-fast (код 2, сообщение о п. 12); токен применяется независимо от
    `admin_token_fallback` (в этом режиме он не fallback, а единственный
    метод). Лог «аутентификация включена (admin-token, SSO выключен)».
- Обратная совместимость: dev/тесты без токена и SSO — прежний
  прозрачный режим (тест TestNoAuthDevMode / TestDevModeUnchanged).
  Стенд и smoke работают с `CLASSIFIER_ADMIN_TOKEN` — вход через /login
  (UI) и X-Admin-Token (API), как раньше задумано протоколами.
- Побочный эффект подтверждён: rate-limit субъектов (S9-6) теперь
  действует и в token-only режиме (burst на стенде → 429).

## Тесты

- api: `TestAdminTokenOnlyMode` (401 без/с неверным, 200 с верным, RBAC
  export), `TestNoAuthDevMode` (dev passthrough не сломан).
- web: `login_test.go` — страницы закрыты без сессии (302/403), полный
  флоу логина (форма → 403 на неверный → 302+cookie на верный → 200 на
  /scans), brute-force 429 после серии неудач, dev-режим без токена.
- Локально: `go vet`, build, `go test ./...` — зелёные. `go test -race`
  (api, web, clickhouse) — на стенде Linux (gcc доустановлен): зелёные.
  На Windows race недоступен (нет gcc, -race требует cgo) — прогон
  перенесён на стенд (toolchain go1.27.3 + vendor в /tmp/gotc).

## Проверка на стенде

Сборка `v0.1-41-g55d99c0-dirty-stand` задеплоена на 192.168.31.248;
протокол — дополнение в `docs/validation/2026-11-01-stand-deployment.md`
(п. 5): без токена 401/302, с токеном 200, UI-логин, 429 на burst,
скан ch-test без INFORMATION_SCHEMA, serve fail-fast без токена.
