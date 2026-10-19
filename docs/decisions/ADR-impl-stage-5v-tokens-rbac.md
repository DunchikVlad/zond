# ADR-impl: инкремент 5в (часть 1) — API-токены, RBAC, admin-token fallback

Дата: 2026-10-19
Статус: accepted (часть 1 инкремента 5в; SAML SP — ADR дополнится в 5в-5)
Связь: blueprint п. 11.2 (аутентификация API), п. 11.3 (RBAC, admin-token),
п. 14.2 (api_tokens, события auth/authorization/admin), ADR-0011,
ADR-impl-5а (аудит), ADR-impl-5б (REST API).

## D1. Ключи токенов — argon2id, показ один раз

`zond token issue` генерирует ключ `zt_` + base64url(32 байта crypto/rand),
показывает его один раз в stdout; в `api_tokens` — только
`argon2id$<salt>$<hash>` (параметры OWASP: t=1, m=64MiB, p=4, ключ 32Б).
Blueprint п. 14.2 предписывает argon2; библиотека `golang.org/x/crypto` уже
была транзитивной зависимостью — новых внешних зависимостей не добавлено
(промоутнута в direct). Сверка — constant-time compare по хэшу.

**Отклонённая альтернатива:** sha256(key) — быстрый хэш уязвим к
перебору при утечке БД; ключи высокоэнтропийные (256 бит), поэтому argon2
здесь — избыточная, но бесплатная и предписанная blueprint стойкость.

## D2. ResolveToken — перебор кандидатов, а не индекс по хэшу

Хэш argon2id солёный → по ключу нельзя построить индекс БД. ResolveToken
сверяет ключ со всеми **неотозванными** токенами (constant-time per hash).
Число живых токенов — единицы-десятки (CI/интеграции), стоимость одной
сверки ~50 мс приемлема; отзыв мгновенный бесплатен (revoked_at ≠ '' →
кандидат не участвует). При росте числа токенов — префикс-ключ `zt_<id>_…`
(идентификатор внутри ключа, миграция формата) — зафиксировано как путь,
не реализовано за ненадобностью MVP.

## D3. last_used_at — троттлинг до раза в час

П. 14.2 прямо: `last_used_at` обновляется не чаще раза в час — CI-интеграция
с сотнями запросов в минуту не превращает каждый запрос в UPDATE по
единственному соединению store (SetMaxOpenConns(1)).

## D4. Цепочка субъекта: SSO-сессия → Bearer-токен → admin-token

`resolveSubject` проверяет cookie-сессию, затем `Authorization: Bearer`,
затем `X-Admin-Token` (fallback). Невалидный Bearer **не проваливается** в
fallback: предъявивший токен аутентифицируется токеном — иначе опечатка в
токене молча «повышается» до admin при включённом fallback.

Admin-token — только из env `CLASSIFIER_ADMIN_TOKEN` и только при
`admin_token_fallback: true` (п. 11.3); каждое использование аудируется
`auth/admin_token_used` с `details.level=warn` (п. 14.2). Штатный режим —
`admin_token_fallback: false` → fallback отсутствует.

## D5. RBAC: роли для людей, scope для машин

SSO-субъекты проверяются по матрице ролей п. 11.3 (admin — всё, viewer —
просмотр). API-токены — по scope `read|review|export|admin` (п. 14.2), где
`admin` включает остальные; старт/стоп сканов отдельного scope не имеет —
только admin (программный старт сканов = привилегированная операция).
Аудит-просмотр — только роль admin / scope admin (п. 14.2).

Отказы 401 (нет/битые креденшелы) и 403 (роль/scope недостаточна)
аудируются: `auth/api_auth_failure` и `authorization/forbidden` с
actor/ролью/действием/путём — best effort (отказ отдаётся клиенту даже при
недоступности аудита; сам защищаемый ресурс при этом не выдаётся).

## D6. Actor propagation через ctx, а не глобальное состояние

`withAuth` кладёт `auth.Subject` в ctx; обработчики берут actor из ctx
(`actorFromCtx`): ревью (`reviewed_by`, review_events, аудит), экспорт,
стоп скана, старт скана (через `ScanRunner.Start(..., actor)` — аудит
движка scan_start/finish/agent_call идёт от имени инициатора). Режим без
SSO (`sso.enabled: false`) — прозрачный 5б: actor `api`, все маршруты
открыты; поведение обратно совместимо.

## D7. Health/ready — вне аутентификации

`/api/health`, `/api/ready` открыты: liveness/readiness-пробы оркестратора
не несут креденшелов; разглашения нет (status-only ответы, ADR-impl-5б
security).

## D8. Граница части 1: SAML SP отсутствует

В 5в-1…5в-4 SSO-сессии создаются только программно (тесты); SAML-флоу
(metadata/login/ACS/SLO, JIT-прvisioning, маппинг ролей из атрибута,
refresh метаданных IdP 24ч, Keycloak в compose) — часть 2 (5в-5). Интерфейс
`SessionStore` и формат actor `sso:<subject>` уже зафиксированы и покрыты
тестами middleware — 5в-5 добавляет лишь выдачу сессий через SAML, не меняя
API-слой.
