# Прогресс: этап 8, инкремент 8-2 — per-source лимиты и окна сканирования

Дата: 2026-10-24
Исполнитель: агент сессии (код + док + юнит-тесты)
Статус: **done** (S8-2; п. 13.2 закрыт целиком: S8-1 — breaker/retry/resume,
S8-2 — лимиты источника и окна; юнит-тесты новых путей — коммит `4fb7d61`).
Следующие шаги: SIEM-sink (опция п. 14.2), LICENSE (владелец),
LLM-метрики DoD (нет стенда), живой прогон S8-2 на стенде (выключен).

## 1. Цель

Blueprint п. 13.2 (resource governance), остаток после S8-1: лимиты на
источник в записи `sources` `connections.yaml` — `max_concurrent_scans`
(default 1), `max_concurrent_tables` (default 2), таймаут запроса к БД
(default 5 мин); окна сканирования (опция) — `scan_window: "02:00-06:00"`,
старт вне окна откладывается шедулером.

## 2. Что сделано

| Чанк | Результат |
|---|---|
| Лимиты, конфиг | `Source.MaxConcurrentScans/MaxConcurrentTables/QueryTimeoutS` + аксессоры с дефолтами спецификации (1/2/300 с); валидация fail-fast (отрицательные отклоняются, сообщение с дефолтом); пример в `configs/connections.yaml` |
| Лимиты, движок | `Config.MaxTables/QueryTimeout`; `TableGate` — блокирующий ctx-aware семафор таблиц прогона; `scanTablesParallel` — пул из MaxTables воркеров, результаты применяются в порядке `ListTables` (серия breaker'а и счётчики идентичны последовательному пути; breaker прекращает подачу, начатые таблицы коммитятся — п. 13); `queryCtx` — дедлайн `query_timeout_s` на каждый запрос (схема/счёт/сэмпл), общий дедлайн прогона — родительский ctx |
| Потокобезопасность движка | Разделяемое состояние прогона под мьютексами: кластерер (`cluMu`), счётчики экономики (`statsMu`), стоимость/бюджет/кэш прайса (`callsMu`); буферы вызовов/аудита таблицы — локальные `tableState` (бывшие `Engine.calls/events`), коммит — в той же транзакции вердиктов (п. 13); чтение бюджета/счётчиков — снимками (`budgetHit`, `statsSnapshot`, `costSnap`) |
| Лимиты, serve | `engineRunner`: семафор `max_concurrent_scans` на источник (map source→chan; 0 → default 1) — повторный старт сверх лимита отклоняется 502 `source_unavailable` до подключения; слот освобождается по завершении прогона |
| Лимиты, CLI | `scan` передаёт `TablesLimit()/QueryTimeout()` источника в конфиг движка; `max_concurrent_scans` в CLI не применим (один прогон на процесс) |
| Окна | `config.Window`/`ParseWindow` (строгий `HH:MM-HH:MM`, локальное время инстанса, окно через полночь `22:00-02:00`, `start == end` отклонено как двусмысленное); `Source.ScanWindow` с валидацией при загрузке |
| Окна, scheduler | Срабатывание cron вне окна → старт откладывается до `NextStart` разовым таймером; при срабатывании таймера окно проверяется заново (сдвиг часов → повторное откладывание); аудит `scheduler/scan_deferred` {source, window_start, delay_s}, actor scheduler (п. 14.2); `Stop()` снимает отложенные таймеры; ручные старты (API/CLI) окном не ограничиваются — спецификация откладывает только шедулер |
| Отчёт | `Report` дополнен применёнными лимитами (`max_concurrent_tables`, `query_timeout`) — видны в выводе `scan` |

## 3. Ключевые решения

См. `docs/decisions/ADR-impl-stage-8-source-limits.md`. Кратко: семафоры
сканов — в памяти runner'а (как breaker, ADR-impl S8-1 D1); параллелизм —
по таблицам, не по колонкам (соединение драйвера не делится; чекпоинт п. 13
— таблица); детерминизм breaker-серии — применение результатов в порядке
списка таблиц; окно — только шедулер (ручной старт — осознанное действие
оператора); локальное время инстанса (как cron robfig), DST не учитывается.

## 4. Проверки (протокол — docs/validation/2026-10-24-stage-8-2.md)

- `make ci` (fmt + vet + build + test) — зелёный; `make test-race` — зелёный
  (полный прогон `-race ./...`: тронута конкурентность движка).
- `zond config validate` на `configs/` — OK.
- Юнит-тесты новых путей — коммит `4fb7d61` (config window, параллельные
  воркеры scanengine, deferral scheduler'а, семафор runner'а). Тесты
  нашли и подтвердили исправление дефекта коллектора `scanTablesParallel`
  (дедлок/зависание при остановке feeder'а — буфер results + stopFeed +
  закрытие после wg.Wait).
- Живой прогон на стенде не выполнялся: стенд 192.168.31.* выключен
  (сообщение владельца 2026-10-24).

## 5. Изменённые файлы

Новые: `internal/config/window.go`, `internal/scanengine/tablegate.go`,
`internal/scanengine/tablestate.go`.
Изменённые: `internal/config/config.go` (поля Source + дефолты + валидация),
`internal/scanengine/engine.go` (Config, параллельный путь, queryCtx,
потокобезопасность, Report), `internal/scheduler/scheduler.go` (окна,
deferScan, таймеры в Stop), `cmd/zond/main.go` (семафор сканов в runner,
проводка лимитов CLI/serve), `configs/connections.yaml` (пример полей).
