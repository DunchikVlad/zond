# Прогресс: этап 4 (ядро) — LLM-слой: Agent Proxy + ensemble + эскалация

Дата: 2026-10-18
Исполнитель: Coordinator / Stage 4 (инкремент a — ядро)
Статус: **частично done** (ядро LLM: proxy/mask/ensemble/escalation/agent-check;
кэш, agent_calls, бюджет, egress — инкременты 4б/4в, требуют миграций и store)

## 1. Цель

Этап 4 blueprint п. 21 (ядро): Agent Proxy — изоляция, маскирование, ретраи;
YAML-реестр агентов; ансамбль + эскалация (п. 7); изоляционные тесты; fake-LLM;
`agent-check` CLI.

## 2. Выполненные чанки

| Чанк | Результат |
|---|---|
| S4a-1 | `mask/`: маскирование PAN (6+4), телефон (код+2), email (local→`a***`), IP (`10.0.0.*`), ИНН/СНИЛС/счёт (1+1), FREE_TEXT (усечение); исключение значений <5 символов (п. 10.2). Табличные тесты + fuzz (7.3M execs, 0 падений) |
| S4a-2 | `prompts/`: версионируемые промпты (system с enum лейблов + семантика confidence + анти-инъекция; user-конверт п. 5.3 в `<values>…</values>`; режим верификатора confirm\|reject). `Version = "1"` |
| S4a-3 | `agentproxy.Proxy`: единственная точка вызова LLM (п. 10.1); OpenAI-compatible запрос; строгая валидация ответа по схеме п. 5.3 (label из таксономии, confidence 0..1, sensitivity enum, reason_ru 1..300); ретраи невалидных ответов/сбоев с экспоненциальной паузой (п. 6); Classify + Verify |
| S4a-4 | Изоляционные тесты (п. 16.3): fake-LLM (httptest) записывает тело; авто-тест отсутствия сырых PAN/телефонов/ИНН/email, имён БД/таблиц/хостов/путей; конверт только model+messages; каждый вызов независим (system+user, нет истории); ретрай невалидного ответа; small_sample без вызова |
| S4a-5 | `ensemble`: полная версия п. 7 — правило 1 (checksum 0.99), взвешенное голосование (meta 1.0/rules 1.5/llm 1.2), порог+отрыв ≥0.3 → auto_accepted, серая зона → сигнал эскалации, `ApplyVerifier` (confirm +0.1 cap 0.95; reject → лейбл верификатора, пересчёт по порогам). Детерминизм: tie-break лексикографический, round4 |
| S4a-6 | `scanengine`: серый коридор LLM (п. 7) — вызов классификатора только при `enoughForLLM` (сэмпл ≥ min, null ≤0.95) и решении в серой зоне; эскалация в верификатор; `prompt_version` в вердикте; checksum не переопределяется. E2E на fake-LLM |
| S4a-7 | `agent-check` CLI: preflight реестра (env разрешены), опц. `-online` пробный вызов; exit-коды. depguard `llm-only-via-agentproxy`: net/http вне agentproxy запрещён (п. 10.1) |

## 3. Ключевые решения и находки

- **Изоляция двумя уровнями**: (1) mask исключает значения <5 символов и маскирует
  ПИИ до proxy; (2) авто-тест п. 16.3 проверяет тело запроса на сырые ПИИ/имена;
  (3) depguard запрещает net/http вне agentproxy. Проверено: net/http вне
  agentproxy отсутствует в кодовой базе.
- **Ретрай невалидного ответа внутри `call`**: валидатор передаётся в ретрай-цикл,
  поэтому невалидный JSON/label/confidence ретраится как и сетевой сбой (п. 6) —
  иначе невалидный ответ доходил до вызывающего без ретрая (найдено тестом).
- **Верификатор строго по п. 5.3**: `confirm` с чужим label — ошибка (защита от
  «подтверждения не того»); `reject` требует альтернативный label из таксономии.
- **phone 0.70 → pending без LLM**: E2E этапа 1 ожидал auto_accepted для phone
  (2/3 валидных); полный ансамбль п. 7 требует conf ≥ tau_accept И отрыв ≥ 0.3 —
  0.70 < 0.80 → серая зона → pending (без LLM) или эскалация (с LLM). Это
  корректное поведение; тест обновлён, добавлен E2E эскалации.
- **nil-защита LLM-ответов** в engine: fake/реальный LLM может вернуть (nil, nil) —
  добавлены проверки `res != nil`/`vr != nil` (найдено зависшим тестом).

## 4. Проверки (протокол — docs/validation/2026-10-18-stage-4.md)

- `go build`, `go vet`, `gofmt -l` — чисто.
- `go test ./...` — все пакеты ok, регрессий нет.
- `go test -race ./internal/agentproxy/... ./internal/ensemble/ ./internal/scanengine/` — зелёный.
- Изоляционные тесты — все PASS (нет сырых ПИИ/имён, независимость вызовов, ретрай).
- `zond agent-check` (ci.env) — 2 агента OK (offline-режим).

## 5. Изменённые файлы

`internal/agentproxy/{proxy,proxy_test}.go`, `internal/agentproxy/mask/{mask,mask_test}.go`,
`internal/agentproxy/prompts/prompts.go`, `internal/ensemble/ensemble{,_test}.go`,
`internal/scanengine/engine{,_test}.go`, `cmd/zond/main.go`, `.golangci.yml`;
удалены doc.go-заглушки agentproxy/mask/prompts/ensemble.

## 6. Не вошло в инкремент (инкременты 4б/4в, blueprint п. 10)

- **Кэш вердиктов** (п. 10.5): таблица `verdict_cache`, ключ sha256(agent_id|model|
  prompt_version|taxonomy_version|mask_profile_version|fingerprint(values)), TTL 30д —
  требует миграции goose и пакета `internal/fingerprint`.
- **Учёт вызовов** (п. 10.6): таблица `agent_calls` в одной транзакции с вердиктом —
  требует миграции и store-изменений.
- **Лимиты/бюджет** (п. 10.4): семафор конкурентных вызовов, rate-limit, budget-стоп
  `cost_scan_limit_usd` → `budget_exceeded`.
- **Egress/контур** (п. 10.7): allowlist (пуст по умолчанию, RFC 1918 + loopback),
  флаг `offline`, локальные OpenAI-совместимые эндпоинты.
- **Кластеризация** (п. 7.6): fingerprint кластеров, представитель, propagation —
  пакет `internal/fingerprint` (заглушка этапа 0), действует до слоя 2.

## 7. Следующие шаги

1. Инкремент 4б: `internal/fingerprint` + кэш вердиктов (миграция `verdict_cache`) +
   кластеризация колонок (п. 7.6).
2. Инкремент 4в: `agent_calls` (миграция) + учёт в транзакции, семафор/rate-limit/
   бюджет, egress-allowlist + `offline`.
3. Подключение LLM-слоя в `runScan` (чтение агентов из detectors.yaml, построение
   proxy, `SetLLM`) — сейчас слой 2 доступен через `Engine.SetLLM`, но CLI его не
   подключает (нет живого эндпоинта на стенде).
4. Этап 5: Store + API + веб-UI + SSO + аудит.
