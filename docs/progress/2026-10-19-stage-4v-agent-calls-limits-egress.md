# Прогресс: этап 4, инкремент 4в — agent_calls + лимиты/бюджет + egress

Дата: 2026-10-19
Исполнитель: Coordinator / Stage 4 (инкремент в — завершение LLM-слоя)
Статус: **done** (слой 2 LLM закрыт по п. 10 blueprint; остаток этапа 4 — не входил в инкременты)

## 1. Цель

Завершить LLM-слой (blueprint п. 21, этап 4; разложение на инкременты — в
`docs/progress/2026-10-18-stage-4-llm-core.md` и
`docs/progress/2026-10-19-stage-4b-fingerprint-cache.md`, раздел «Следующие шаги»):

1. **Учёт вызовов** (п. 10.6, п. 11.1, п. 13): таблица `agent_calls` +
   прайс-лист `model_prices`; каждая строка — в одной транзакции с вердиктом.
2. **Лимиты/бюджет** (п. 10.4): семафор конкурентных вызовов (default 8),
   глобальный rate-limit rps, budget-стоп `cost_scan_limit_usd` →
   статус скана `budget_exceeded`.
3. **Egress-политика** (п. 10.7): allowlist по умолчанию пуст → только
   loopback/RFC 1918; публичный эндпоинт — только явной записью в
   `agents.*.allowlist`; `offline: true` запрещает всё вне allowlist. SSRF.
4. **CLI**: `zond scan -llm` подключает слой 2 из реестра detectors.yaml
   (раньше `Engine.SetLLM` не вызывался никем — слой 2 был доступен только
   из тестов).

## 2. Что сделано

| Чанк | Результат |
|---|---|
| 4в-1 | Миграция `0003_agent_calls.sql`: `agent_calls` (FK на scans/verdicts, CHECK status ok\|error\|cache_hit, индекс по scan_id) + `model_prices` (PK model+effective_from, seed gpt-4o-mini 0.15/0.60, gpt-4o 2.50/10.00 за 1M токенов). Store: `SaveVerdictsWithCalls` (одна транзакция вердикты+вызовы, п. 13), `SaveVerdicts` — обёртка (API этапа 1 сохранён), `ListAgentCalls`, `PriceFor`, `NewCallID` (rand hex16) |
| 4в-2 | Прокси отдаёт `Usage` (prompt/completion tokens из OpenAI-ответа; nil, если агент не вернул — локальные контуры) и `Latency` (полный call() с ретраями) в `ClassifyResult`/`VerifyResult` |
| 4в-3 | `internal/agentproxy/limits.go`: `Gate` — семафор (default 8, п. 10.4) + rate-limit (интервал 1/rps; 0 — без лимита); `Acquire`/`Release`, отмена контекста не теряет слот. Опция `WithGate`; один вызов = один слот (п. 10.3/10.4), Gate разделяется прокси скана |
| 4в-4 | `internal/agentproxy/egress.go`: `CheckEgress(endpoint, Policy)` — резолв host (fail-closed: не разрешился → запрещён), allowlist-записи IP/CIDR (по resolved IP) или hostname; нулевая Policy = базовая политика п. 10.7 (loopback/RFC 1918 разрешены, публичные нет); `offline` запрещает всё вне allowlist. Проверка — всегда в `New` (нельзя отключить), ошибка = прокси не конструируется |
| 4в-5 | Движок: буфер `agent_calls` на таблицу (коммит с вердиктами, п. 13; буфер failed-таблицы сбрасывается и не протекает в соседний коммит), записи ok/error/cache_hit (cache hit — `cached=1` без токенов, метрика доли кэша п. 17), стоимость по `model_prices` (округление 6 знаков, ленивый кэш прайса на скан; модели нет в прайсе → cost 0), budget-стоп: после превышения `CostScanLimitUSD` вызовы прекращаются, колонки помечаются `evidence.budget_exceeded=true`, статус скана `budget_exceeded` (приоритет над done/partial). Report/stats_json: `llm_errors`, `tokens_in/out`, `cost_usd` |
| 4в-6 | Config: `proxy:` (offline, max_concurrent, rate_limit_rps, cost_scan_limit_usd) + `agents.*.allowlist` с валидацией записей (IP/CIDR/hostname), fail-fast в `config validate`. `configs/detectors.yaml` дополнен |
| 4в-7 | CLI: `zond scan -llm` — fail-fast сборка LLM-слоя (env ключей основного и верификатора, Gate, egress), композит `llmComposite` (Classify → agents[0], Verify → escalate_to, п. 7 правило 4); `agent-check` строит прокси и в offline-режиме — egress-запрет = FAIL (preflight п. 15.3) |
| 4в-8 | Тесты: store (round-trip, FK-целостность, прайс), gate (пик конкурентности ≤ лимита, rate-limit по времени, отмена ctx, default 8), egress (таблично, IP-литералы + localhost, без внешнего DNS), engine E2E (записи и атомарность, budget-стоп, ошибки classify+verify, буфер per-table) |

## 3. Ключевые решения

- **Egress — всегда включён.** Первая редакция 4в отключала проверку при
  нулевой Policy; ревью показало, что это размывает дефолт п. 10.7 (публичный
  эндпоинт без allowlist проходил в штатном wiring). Конструктор прокси теперь
  всегда проверяет эндпоинт; нулевая Policy — это базовая политика пункта
  (private/loopback ок, публичное — нет). См. `docs/decisions/ADR-impl-stage-4v-agent-calls-limits-egress.md`.
- **Поведение при ошибке classify → verify всё равно вызывается.** Решение
  остаётся в серой зоне, эскалация (п. 7 правило 4) — независимое второе
  мнение; обе ошибки пишутся в agent_calls со статусом error.
- **Budget-стоп = «LLM выключен», а не «скан прерван».** Дешёвые слои 0/1
  продолжают классифицировать оставшиеся таблицы; колонки, требовавшие LLM,
  остаются pending с пометкой. Это чтение п. 10.4 («неотвеченные колонки →
  pending») зафиксировано в ADR (альтернатива — прервать скан досрочно).
- **Цены моделей — данные БД (п. 11.1), не конфига.** Seed известных моделей
  миграцией; пополнение прайса — SQL в `model_prices`. Модель без цены:
  учитывается с cost 0 (локальные контуры бесплатны — budget-стоп по деньгам
  для них не срабатывает, что корректно).
- **Кэш-hit тоже пишет agent_calls (cached=1, без токенов)** — иначе метрика
  «доля решённого из кэша» (п. 17) не восстанавливается из БД.
- **`-llm` — опция scan.** Без живого эндпоинта на стенде прежнее поведение
  (слои 0–1) не должно было сломаться; fail-fast только при явном `-llm`
  либо в agent-check (preflight).
- **Эскалация в CLI — композит, а не правка движка.** Движок по-прежнему
  видит один `LLMClassifier`; кто звонить на Verify (основной агент или
  escalate_to) решает wiring (`llmComposite` в cmd). Движок и его тесты не
  изменились в этой части.

## 4. Проверки (протокол — docs/validation/2026-10-19-stage-4v.md)

- `go build`, `go vet`, `gofmt -l` — чисто; `golangci-lint` — 0 issues.
- `go test ./...`, `go test -race ./internal/...` — все пакеты ok.
- `make config-check` — OK (блок `proxy:` принят).
- `zond agent-check` с демо-конфигом: оба агента FAIL («host api.example не
  разрешился, fail-closed») — корректный дефолт п. 10.7; с loopback-эндпоинтом
  (локальный контур) — оба OK.
- E2E: 4 ok-записи + 1 cache_hit на сценарий кэша; budget-стоп останавливает
  вызовы после порога; failed-таблица не протекает в коммит соседней.

## 5. Изменённые файлы

- `internal/verdict/store/`: `calls.go` (новый), `calls_test.go` (новый),
  `migrations/0003_agent_calls.sql` (новый), `store.go` (SaveVerdicts → обёртка).
- `internal/agentproxy/`: `proxy.go` (Usage/Latency, Option, New→error, egress
  всегда), `egress.go`, `limits.go` (новые), `egress_test.go`, `limits_test.go`,
  `proxy_test.go` (адаптация под сигнатуру New).
- `internal/scanengine/`: `engine.go` (agent_calls, budget, экономика),
  `budget_calls_test.go` (новый), `engine_test.go`/`cache_cluster_test.go`
  (сигнатура SetLLM).
- `internal/config/config.go` (ProxyConfig, allowlist + валидация),
  `configs/detectors.yaml` (блок proxy), `cmd/zond/main.go` (-llm, композит,
  agent-check egress).

## 6. Не вошло (переносится)

- Расписание пересканов и TTL-прочистка `verdict_cache` (п. 15.4) — пакет
  scheduler пока пуст; пора в этап 5.
- Hot-reload `detectors.yaml` (ADR-0014) — контракт в конфиге есть, механизма
  watch ещё нет.

## 7. Следующие шаги

1. **Этап 5** (blueprint п. 21): Store + API + веб-UI + SSO + аудит —
   оставшаяся схема БД п. 11.1 (`review_events`, `users`, `audit_log`,
   `api_tokens`, `model_prices`-администрирование), REST API п. 11.2,
   страницы UI п. 11.3, SSO SAML 2.0 (ADR-0011), аудит hash-chain
   (ADR-0013), scheduler (cron, TTL-прочистка, окна сканирования п. 13.2).
2. Этап 6 (eval-harness), этап 7 (харденинг: Vault ADR-0012, backup/doctor).
