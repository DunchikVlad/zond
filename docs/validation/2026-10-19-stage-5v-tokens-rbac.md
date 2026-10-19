# Валидация: этап 5, инкремент 5в (часть 1) — API-токены, RBAC, admin-token

Дата: 2026-10-19
Объект: шаги 5в-1…5в-4, см. `docs/progress/2026-10-19-stage-5v-tokens-rbac.md`,
`docs/decisions/ADR-impl-stage-5v-tokens-rbac.md`

## 1. Что проверялось и как

| Проверка | Команда | Результат |
|---|---|---|
| Сборка | `go build ./...` | чисто |
| Vet | `go vet ./...` | чисто |
| Форматирование | `gofmt -l .` | пусто |
| Unit + E2E | `go test ./...` | все пакеты ok |
| Race (изменённые пакеты) | `go test -race ./internal/api/ ./internal/auth/ ./internal/verdict/store/` | ok |
| Миграция 0006 | `TestMigrationsUpDownUp` (store) | up→down→up зелёный |

## 2. Live-smoke (токены + auth serve)

Сценарий: `zond token issue -name ci-bot -scopes read,export` →
`zond serve` с `sso.enabled: true` (временная копия configs).

| Шаг | Ожидание | Факт |
|---|---|---|
| `token issue` | ключ показан один раз, в list — без ключа | OK (`zt_…`, 90д TTL, expires выведен) |
| `token list` | JSON без хэшей, поля id/name/scopes/expires | OK |
| `GET /api/v1/scans` без креденшелов | 401 | **401** |
| то же с `Authorization: Bearer <key>` | 200 | **200** |
| `GET /api/health` без креденшелов | 200 (открыт) | **200** |
| `token revoke -id …` → повторный запрос | мгновенный 401 | **401** |
| `X-Admin-Token` (CLASSIFIER_ADMIN_TOKEN задан) | 200 | **200** |

## 3. Что подтверждено тестами

- **Store tokens** (`tokens_test.go`): JIT-upsert пользователя (роль
  обновляется при повторном входе, created_at стабилен); issue+resolve
  (argon2id-сверка, чужой ключ → ErrTokenInvalid, default TTL 90д,
  аудит token_issue от issued_by); троттлинг last_used_at (в пределах часа
  не двигается, после — обновляется; round-trip секундной точности);
  revoke мгновенный + повторный revoke падает + аудит token_revoke +
  цепочка сходится; просроченный токен недействителен; валидация scopes;
  неуспешные выпуски не аудируются; list без хэшей, свежие первыми,
  revoked-флаг.
- **Auth-пакет** (`auth_test.go`): вся RBAC-матрица п. 11.3 (10 кейсов);
  MaxRole; жизненный цикл сессий (create/get/delete), ленивое истечение TTL;
  Subject round-trip в ctx.
- **API auth** (`internal/api/auth_test.go`, 8 E2E): режим без SSO —
  прозрачный (actor api); 401 без креденшелов + аудит api_auth_failure;
  невалидный Bearer → 401 (не fallback); RBAC по scope — reader/exporter/
  reviewer/admin по действиям, 3 отказа 403 в аудите с actor/действием,
  цепочка сходится; actor propagation — ревью от token:reviewer виден в
  аудите, reviewed_by, review_events; admin-token — 200 + аудит
  admin_token_used с level=warn, неверный/отключённый → 401; SSO-сессия —
  viewer 403 на ревью, admin-сессия 200 с actor sso:boss@corp, мёртвая
  сессия 401; health/ready открыты под включённой аутентификацией.

## 4. Не проверено / ограничения

- **SAML-флоу не существует** (5в-5): SSO-сессии в тестах создаются
  напрямую в SessionStore — проверен контракт middleware, не SAML.
- golangci-lint локально не установлен — прогонит CI (как в 5б).
- Нагрузка resolveToken не измерялась (перебор + argon2id ~50 мс/кандидат);
  при десятках токенов и 100 req/s это узкое место — путь оптимизации
  зафиксирован в ADR D2 (префикс-ключ с id).

## 5. Остаточные риски

- До 5в-5 включение `sso.enabled: true` оставляет единственные способы
  входа — API-токены и admin-token; SAML-логина нет. Документировано в
  прогрессе; конфиг-дефолт `sso.enabled: false` (режим 5б) не затронут.
- Admin-token в env — виден в `/proc/<pid>/environ` на хосте; это
  осознанный fallback-механизм п. 11.3 (bootstrap/аварийный), штатный
  режим — `admin_token_fallback: false`.
