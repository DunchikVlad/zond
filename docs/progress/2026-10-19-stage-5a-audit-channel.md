# Прогресс: этап 5, инкремент 5а — аудит-канал (ADR-0013)

Дата: 2026-10-19
Исполнитель: Coordinator / Stage 5 (инкремент а — аудит)
Статус: **done**

## 1. Цель

Закрыть ядро security audit log (blueprint п. 14.2, ADR-0013): append-only
таблица `audit_log` с цепочкой хэшей против подмены/удаления, запись событий
из движка (жизненный цикл скана, каждый вызов LLM), программная верификация
цепочки и выгрузка. Первый инкремент этапа 5 — дальше по этапу: REST API,
веб-UI, SSO (акторы `sso:<subject>` вместо `cli`), страница `/audit`.

## 2. Что сделано

| Чанк | Результат |
|---|---|
| 5а-1 | Миграция `0004_audit_log.sql`: `audit_log(seq AUTOINCREMENT PK, ts, actor, category, action, target, details_json, prev_hash, entry_hash)` + индексы (ts, actor) + триггеры `audit_log_no_update/no_delete` (RAISE ABORT — append-only на уровне БД; тело триггеров в `+goose StatementBegin/End` — иначе goose режет по ';') |
| 5а-2 | Пакет `internal/audit`: `Event`/`Entry`, каноническая форма (UTF-8 JSON с сортированными ключами над {seq,ts,actor,category,action,target,details_json} + "\n"; детерминизм — сортировка ключей stdlib), `entry_hash = sha256(prev_hash\|canonical)`, genesis prev_hash = "" (ADR-impl-5а), `AppendTx` (продолжение цепочки внутри чужой транзакции), `Verify` (пересчёт, первый разрыв: неверный prev_hash или entry_hash), `List` (фильтры actor/category/since/scan_id) |
| 5а-3 | Store-интеграция: `AppendAudit` (отдельная транзакция для событий скана), `SaveVerdictsWithCalls` расширена параметром events — вердикты + вызовы + аудит таблицы коммитятся ОДНОЙ транзакцией (п. 13 + п. 14.2: действие без аудита не совершено; FK-провал вызова откатывает и события); `AuditVerify`, `AuditList` |
| 5а-4 | Движок: буфер аудит-событий таблицы (1:1 с agent_calls); `scan_start` (после SaveScan; ошибка аудита отменяет скан) и `scan_finish` (внутри finish, сводка stats) с актором из `Config.Actor` (default "cli"); событие `agent_call` на каждый вызов/ошибку/cache-hit со ссылками `call_id`, `scan_id`, `verdict_id` и экономикой (п. 14.2: каждый вызов — в аудите) |
| 5а-5 | CLI: `zond audit verify` (пересчёт цепочки, exit 1 при разрыве, ссылка на runbook) и `zond audit export` (фильтры `-actor/-category/-since/-scan/-out`, JSON; сам экспорт аудируется ДО выдачи данных — fail-closed) |
| 5а-6 | Тесты: audit (цепочка, детерминизм канонической формы, обнаружение подмены entry_hash/prev_hash, genesis, фильтры), store (триггеры блокируют UPDATE/DELETE, цепочка через пачки, атомарный откат событий), engine E2E (6 событий на скан с LLM: start+finish+4 вызова; скан без LLM — start+finish; цепочка сходится) |

## 3. Ключевые решения

- **Аудит в транзакциях домена, а не отдельным писателем.** `audit.AppendTx`
  вставляет события в tx вердиктов/вызовов — атомарность «действие+аудит»
  без отдельной writer-очереди. Порядок цепочки гарантирован
  `SetMaxOpenConns(1)` + последовательным движком (процессная модель
  single-instance, ADR-0014). Ограничение зафиксировано в ADR-impl-5а.
- **Actor = `cli`.** SSO и API-токенов ещё нет; формат `sso:<subject>` /
  `token:<id>` резервируется категориями и полем Actor (п. 14.2).
- **Fail-closed на ошибках аудита:** scan_start без аудита отменяет скан;
  экспорт без аудит-записи не выдаёт данные. На уже падающем пути
  (list tables) scan_finish — best effort.
- **Фильтр scan_id** матчит `target = scan:<id>` и `details_json.scan_id`
  (события вызовов агентов относятся к скану через details, target при этом
  `agent:<id>` — навигация п. 14.2 «по scan_id»).

## 4. Проверки (протокол — docs/validation/2026-10-19-stage-5a.md)

- `go build`, `go vet`, `gofmt` — чисто; `golangci-lint` — 0 issues.
- `go test ./...`, `go test -race ./internal/...` — все пакеты ok.
- `make config-check` — OK (миграция 0004 накатывается на чистую БД;
  `TestMigrationsUpDownUp` проходит — down/up с триггерами).
- CLI-smoke: `audit verify` на пустой БД → OK (0 записей); `audit export` →
  `[]`, повторный export содержит событие `audit_export`, цепочка сходится.

## 5. Изменённые файлы

`internal/verdict/store/migrations/0004_audit_log.sql` (новый),
`internal/audit/{audit.go,audit_test.go}` (заглушка doc.go заменена),
`internal/verdict/store/{audit.go,audit_test.go}` (новые), `calls.go`
(события в tx), `calls_test.go` (сигнатуры), `internal/scanengine/engine.go`
(события, Actor), `audit_events_test.go` (новый), `cmd/zond/main.go`
(`zond audit verify|export`).

## 6. Не вошло (следующие инкременты этапа 5)

- Внешний sink в SIEM (syslog/CEF, локальная очередь повторов — п. 14.2).
- Retention ≥180 дней: автоочистка шедулером (п. 15.4) — вместе с пакетом
  scheduler (cron-пересканы, окна п. 13.2).
- События категорий auth/authorization/review/config/secrets/admin — появятся
  с SSO, REST API и hot-reload detectors.yaml; категории резервированы.
- Страница `/audit` (UI), RBAC «просмотр аудита — только admin» (п. 11.3).
- Подписанные WORM-снапшоты цепочки (п. 14.2, опция).

## 7. Следующие шаги

1. Инкремент 5б: REST API п. 11.2 поверх store (scans/verdicts/review/drift/
   export/stats) — фундамент UI и SSO-интеграции.
2. Инкремент 5в: SSO SAML 2.0 (ADR-0011) — actor `sso:<subject>`, роли,
   JIT-прvisioning, события категории auth.
3. Инкремент 5г: веб-UI (п. 11.3), страница `/audit`, scheduler.
