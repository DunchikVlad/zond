# Прогресс: этап 8, инкремент 8-1 — resource governance (circuit breaker, retry, resume)

Дата: 2026-10-24
Исполнитель: агент сессии
Статус: **done** (S8-1; остаток п. 13.2 — per-source лимиты
`max_concurrent_scans/max_concurrent_tables`, отдельной задачей).
Следующие шаги: эти лимиты, SIEM-sink (опция п. 14.2), LICENSE (владелец),
LLM-метрики DoD (без стенда).

## 1. Цель

Blueprint п. 13.2: сканер не должен деградировать продуктивные БД.
Закрываемая часть: классификация ошибок драйвера, retry только на
retryable, circuit breaker per source (5 подряд failed по причине
`source_overload` → пауза источника 5 мин, скан → `partial`), `--resume`.

## 2. Что сделано

| Чанк | Результат |
|---|---|
| S8-1 | `connector.FailureReason` + классификация: базовые случаи (дедлайн/сетевой таймаут — overload; отмена контекста — нет) + регистрация классификаторов драйверов в init подпакетов (базовый пакет не тянет драйверы): ClickHouse коды 159/202/203/241/252 (timeout, simultaneous queries, no free connection, memory limit, too many parts), MongoDB коды 91/189/10107/13435/13436/11600/11602 (shutdown/stepdown/not-primary) + сетевые ошибки драйвера |
| S8-1 | Движок: retry таблицы до 3 попыток (backoff 250мс/1с, ctx-aware) только на retryable; circuit breaker — серия из 5 подряд overload-failed таблиц обрывает прогон (остальные не тронуты), `Breaker.Trip` ставит источник на паузу 5 мин; повторные прогоны в паузе отказаны до её конца (`SourcePausedError`); аудит `source_paused` (actor прогона, п. 14.2); статус скана partial |
| S8-1 | Resume: миграция 0008 (`scan_tables.reason`), `DoneTables` + `LastCheckpointScan` в store, флаг CLI `scan -resume` (чекпоинт — последний partial/interrupted прогон источника), отчёт показывает `Resume: пропущено N таблиц`; stats_json дополнен `tables_skipped`, `resume_from`, `breaker_tripped` |
| S8-1 | Wiring: serve `engineRunner` шарит один breaker (отказ API до подключения, 502 source_unavailable), CLI — breaker на процесс; причина failed пишется в `scan_tables.reason` |

## 3. Ключевые решения

См. `docs/decisions/ADR-impl-stage-8-resource-governance.md`. Кратко:
breaker в памяти процесса (пауза 5 мин краткоживущая; SQLite-стояние
избыточно); пороги — константы спецификации (5/5 мин); классификаторы
драйверов — регистрация, а не импорты в базовый пакет; retry не
распространяется на ошибки store (там собственная транзакционность).

## 4. Проверки (протокол — docs/validation/2026-10-24-stage-8.md)

- `make ci`, `go test -race` затронутых пакетов, `golangci-lint` — зелёные.
- **Живой прогон на стенде**: реальный ClickHouse, учётка `test` с
  `max_execution_time=0.5` + 6 view `SELECT sleep(1)` → код 159 на сэмплах.
  Скан через API: partial, 7 таблиц, 5 failed, `breaker_tripped=true`;
  второй POST в паузе → отказ с until; аудит `source_paused` в журнале;
  `scan -resume` после снятия ограничения → done 7/7. Стенд восстановлен.

## 5. Изменённые файлы

Новые: `internal/connector/errors.go`, `internal/connector/{clickhouse,mongodb}/errors.go`,
`internal/scanengine/breaker.go`, `internal/scanengine/breaker_e2e_test.go`,
`internal/verdict/store/migrations/0008_scan_tables_reason.sql` (+ тесты классификации).
Изменённые: `internal/scanengine/engine.go` (retry/breaker/resume/reason),
`internal/verdict/store/store.go` (MarkTable+reason, DoneTables,
LastCheckpointScan), `cmd/zond/main.go` (-resume, breaker CLI/serve),
тесты store/engine.
