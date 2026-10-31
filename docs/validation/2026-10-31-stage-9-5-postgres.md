# Валидация S9-5 — PostgreSQL коннектор и динамический выбор СУБД

Дата: 2026-10-31. Инкремент: S9-5.

## Проверки кода

| Проверка | Команда | Результат |
|---|---|---|
| Форматирование | `gofmt -l .` | чисто |
| Vet | `go vet ./...` | чисто |
| Сборка | `go build ./...` | OK |
| Unit-тесты | `go test ./...` | все пакеты PASS |
| Race | `go test -race ./internal/connector/... ./internal/config/... ./internal/web/...` | все PASS |
| Контракт PostgreSQL | `go test ./internal/connector/postgres/ -run TestConformance` | SKIP (нет Docker) |
| Классификация ошибок | `go test ./internal/connector/postgres/ -run TestClassifyFailure` | 7 кейсов PASS |

## Покрытие тестами

| Пакет | Тесты | Покрытие |
|---|---|---|
| `internal/connector/postgres` | TestConformance (testcontainers), TestClassifyFailure | контракт, классификация ошибок |
| `internal/config` | sourceedit_test (существующие + новые кейсы) | валидация type/DSN/URI/ref |
| `internal/web` | существующие тесты sources | рендер с Types |

## Проверки безопасности

- Секреты: ${ENV}-ссылки проверяются checkSecretRef (fail-closed);
- DSN/URI/ref — ровно одно обязательно;
- Квотирование идентификаторов в SQL (qid) — защита от инъекций;
- Классификация ошибок: retryable только на overload (не на syntax/constraint).

## Ограничения

- Контрактный тест PostgreSQL скипнут без Docker (testcontainers);
- Живой стенд PostgreSQL не поднимался;
- MySQL/MariaDB и MS SQL — следующие шаги.
