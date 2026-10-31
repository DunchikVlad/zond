# S9-5 — выбор СУБД и новый коннектор PostgreSQL

Дата: 2026-10-31. Инкремент: S9-5.

## Основание

- План S9: `docs/progress/2026-10-25-stage-9-plan.md` §6 (S9-5).
- HANDOFF: «Следующий шаг S9-5: выбор СУБД и новые коннекторы (PostgreSQL → MySQL/MariaDB → MS SQL)».
- Blueprint: п. 4 (плагинные коннекторы), п. 9 (специфика БД), п. 12 (конфигурация).

## Реализация

### 1. Коннектор PostgreSQL — `internal/connector/postgres/`

Драйвер `lib/pq` (pure Go, без cgo), `database/sql`-интерфейс (аналогично ClickHouse).

| Метод | Реализация |
|---|---|
| `Ping` | `db.PingContext` |
| `ListTables` | `information_schema.tables` (исключены pg_catalog, information_schema) |
| `GetSchema` | `information_schema.columns`, unwrap типов (character varying→varchar, timestamptz и т.д.) |
| `CountRows` | `SELECT count(*) FROM "schema"."table"` |
| `Sample` | `SELECT ... ORDER BY random() LIMIT N` (п. 5.1: не head-N) |

Классификация ошибок (`errors.go`): pq.Error коды 53300/53400/57P01/57P02/57P03/58030 + сетевые (connection reset/broken pipe/refused) → `ReasonOverload` (retryable). Прочие — `ReasonOther`.

Регистрация: `init()` → `connector.Register("postgresql", ...)`.

### 2. Динамический список типов — S9-5

Было: hardcoded `clickhouse|mongodb` в трёх местах (UI select, валидация sourceedit, сообщение об ошибке).

Стало:
- `internal/web/sources.go`: `Types: connector.Types()` передаётся в шаблон;
- `internal/web/templates/sources.html`: `{{range .Types}}` вместо hardcoded option;
- `internal/config/sourceedit.go`: `strings.Join(connector.Types(), "|")` в сообщении об ошибке; case "postgresql" — dsn (uri неприменим).

### 3. Единая валидация type/DSN/URI/ref

- `postgresql`: только dsn (uri отклоняется), checkSecretRef на ${ENV};
- `clickhouse`: только dsn (uri отклоняется);
- `mongodb`: только uri (dsn отклоняется);
- ref — Vault, без checkSecretRef (секрет не в строке подключения).

## Проверки

| Проверка | Команда | Результат |
|---|---|---|
| Форматирование | `gofmt -l .` | чисто |
| Vet | `go vet ./...` | чисто |
| Сборка | `go build ./...` | OK |
| Unit-тесты | `go test ./...` | все пакеты PASS |
| Race | `go test -race ./internal/connector/... ./internal/config/... ./internal/web/...` | все PASS |
| Контракт PostgreSQL | `go test ./internal/connector/postgres/ -run TestConformance` | SKIP (нет Docker) |

## Ограничения

- Контрактный тест PostgreSQL (testcontainers) скипнут без Docker;
- Живой стенд PostgreSQL не поднимался (нет стенда);
- MySQL/MariaDB и MS SQL — следующие шаги (порядок из плана S9-5).
