# Прогресс: этап 8, инкремент 8-3 — SIEM-sink аудит-журнала (п. 14.2)

Дата: 2026-10-24
Исполнитель: агент сессии
Статус: **done** (S8-3; закрывает опцию п. 14.2 — внешний sink аудита).
Следующие шаги: LICENSE (владелец), LLM-метрики DoD (нет стенда),
живой прогон S8-2/S8-3 на стенде (выключен).

## 1. Цель

Blueprint п. 14.2: «Внешний sink (опция): syslog/CEF или JSON-over-TCP в
SIEM (`audit.sink` в конфиге); при недоступности sink — локальная очередь с
повторной отправкой, потеря событий недопустима». До инкремента журнал
только локальный (audit_log + hash-chain); внешней доставки не было
(архитектура заявляла `audit/ ... SIEM-sink`, карта пакетов — sink).

## 2. Что сделано

| Чанк | Результат |
|---|---|
| Конфиг | `connections.yaml` → `audit.sink {kind, address, proto}`: kind `json-tcp` (NDJSON по TCP) или `syslog` (CEF-строка; proto udp default/tcp); валидация fail-fast (kind+address вместе, proto только для syslog, address = host:port); пример закомментирован в `configs/connections.yaml` |
| Миграция 0009 | `audit_sink_state` — закладка доставки (одна строка на инстанс, ADR-0014): `last_seq` (последний доставленный seq audit_log), `last_error`, `updated_at` |
| Воркер | `internal/audit/sink.go`: `Sink` (nil-safe — sink выключен), `Pump(ctx)` — пакет событий за закладкой (≤128) строго в порядке цепочки; закладка двигается только за подтверждённо доставленное событие; первая неудача останавливает цикл и фиксируется в `last_error`, закладка не двигается → повтор на следующем цикле |
| Провод | `CanonicalEntry` экспортирована: на провод уходит каноническая форма записи (п. 14.2) — NDJSON для json-tcp, CEF-строка (`CEF:0|...|<seq>|audit|...|msg=<canonical>`) для syslog; внешняя сверка hash-chain не зависит от внутреннего формата |
| Очередь | Очередь — **сам append-only журнал**: никаких пометок при записи, никакого dual-write; «потеря недопустима» по построению (закладка не двигается за недоставленное). Порядок сохраняется — SIEM сверяет цепочку напрямую |
| serve | `sinkLoop`: Pump по таймеру 2 с; при ошибке уровня журнала (БД/закладка) — backoff 30 с; остановка по ctx serve |
| doctor | проверка `audit.sink`: backlog закладки (`audit.SinkPending`) — WARN при отставании, OK при пустом; SKIP по отсутствию блока — не показывается (sinkAddr пуст) |
| store | `DB()` — сырое соединение для инфраструктурного чтения очереди sink (один писатель; sink лишь SELECT audit_log + UPDATE закладки) |

## 3. Ключевые решения

См. `docs/decisions/ADR-impl-stage-8-3-siem-sink.md`. Кратко: очередь =
журнал (а не per-event таблица с dual-write — нельзя обойти пути записи:
агент-вызовы в `SaveVerdictsWithCalls`, токены и пр. идут через общий
`audit.AppendTx`); закладка в той же БД (переживает рестарт, single-
instance); порядок строго по цепочке (сверка hash-chain на стороне SIEM);
недоступность sink не роняет запись аудита (fail-closed по журналу,
не по sink); пакет audit не тянет config (зеркальный SinkConfig,
конвертация в cmd).

## 4. Проверки (протокол — docs/validation/2026-10-24-stage-8-3.md)

- `make ci` (fmt+vet+build+test), `make test-race` (полный `-race ./...`) —
  зелёные; `zond config validate` OK.
- Тесты: порядок доставки и отсутствие дублей; retry после недоступности
  (закладка не двигается, `last_error` фиксируется/сбрасывается); догон
  событий между циклами; CEF-фрейминг; `SinkPending`; nil-safe Sink;
  валидация конфига (10 кейсов). In-memory «SIEM» на net.Pipe — без сети.
- Живой прогон на стенде не выполнялся: стенд выключен (192.168.31.*).
- Флаки `internal/audit` под нагрузкой (известная проблема из HANDOFF,
  не затронута инкрементом) в изоляции ok — подтверждено.

## 5. Изменённые файлы

Новые: `internal/audit/sink.go`, `internal/audit/sink_test.go`,
`internal/verdict/store/migrations/0009_audit_sink_state.sql`.
Изменённые: `internal/audit/audit.go` (CanonicalEntry, SinkEntries/
SinkLastSeq/SinkAdvance/SinkPending), `internal/config/config.go`
(блок `audit.sink` + валидация), `internal/config/window_test.go`
(+кейсы sink), `internal/doctor/doctor.go` (проверка audit.sink backlog),
`internal/verdict/store/store.go` (DB()), `internal/verdict/store/audit.go`
(doc: sink по закладке), `cmd/zond/main.go` (auditSinkConfig, sinkLoop,
wiring serve), `configs/connections.yaml` (пример).
