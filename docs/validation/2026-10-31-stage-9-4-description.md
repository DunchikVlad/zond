# Валидация S9-4 — DescriptionRunner

Дата: 2026-10-31. Инкремент: S9-4.

## Проверки кода

| Проверка | Команда | Результат |
|---|---|---|
| Форматирование | `gofmt -l .` | чисто |
| Vet | `go vet ./...` | чисто |
| Сборка | `go build ./...` | OK |
| Unit-тесты | `go test ./...` | все пакеты PASS |
| Race | `go test -race ./internal/scanengine/... ./internal/api/... ./internal/verdict/store/... ./internal/audit/...` | все PASS |
| Миграции | `go test ./internal/verdict/store/ -run TestMigrations` | up/down/up PASS |

## Покрытие тестами

| Пакет | Тесты | Покрытие |
|---|---|---|
| `internal/verdict/store` | TestDescriptionRunCRUD, TestDescriptionRunMigration0013 | CRUD, миграция, индексы |
| `internal/agentproxy` | TestDescribeHappyPath, TestDescribeIsolationNoRawValues, TestDescribeValidationError, TestDescribeEmptyInput | вызов, изоляция, валидация схемы |
| `internal/scanengine` | TestDescriptionRunnerHappyPath, ScanNotFound, NotTerminal, NoLLM, LLMError, PartialMarked, NoVerdicts, Aggregation | оркестрация, статусы, аудит, агрегация |
| `internal/api` | TestDescriptionStart, StartNotFound, StartNotTerminal, StartNoRunner, StartRunnerError, List, ListNotFound, Get, GetNotFound | endpoint'ы, коды ошибок, RBAC |

## Проверки безопасности

- Агрегированный вход: только лейблы/типы/sensitivity/confidence — без сырых
  значений (проверено TestDescribeIsolationNoRawValues: тело запроса не содержит
  имён БД/хостов, только `<data>` с агрегатами);
- Промпт: анти-инъекция через `<data>` разделители (аналогично `<values>` в
  классификаторе);
- RBAC: POST — ActionScan (admin), GET — ActionView (admin+viewer);
- Аудит: description_start/finish/failed с actor, без текста результата;
- Ошибка LLM обрезана до 300 символов (truncateDescriptionErr);
- CSRF: web-форма describe — hidden-поле csrf_token (S8-6 паттерн);
- Экранирование результата в UI: html/template (стандартное, без safeHTML).

## Проверки экономики

- Usage (tokens_in/out) парсится из ответа LLM (п. 10.6);
- cost_usd считается по прайс-листу model_prices (PriceFor);
- Latency — полная длительность вызова включая ретраи.

## Ограничения

- Живой стенд не запускался (LLM — fake в тестах);
- Kimi живой прогон — ждёт пополнения баланса (platform.kimi.com);
- Отмена running-описания не реализована (sync-вызов); interrupted — только
  по ctx-отмене (таймаут агента, default 30s).
