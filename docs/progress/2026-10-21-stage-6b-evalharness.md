# Прогресс: этап 6, инкремент 6б — eval-harness

Дата: 2026-10-21
Исполнитель: агент сессии (этап 6 — «Качество и экономика», blueprint п. 21)
Статус: **done** (S6б). Следующие: S6в — метрики и наблюдаемость (п. 17);
либо этап 7 (харденинг: doctor п. 15.3, backup п. 15.2, Vault ADR-0012, релиз v0.1)

## 1. Цель

Eval-harness (blueprint п. 16.6): прогон каскада классификации по эталонному
датасету S6а, precision/recall/F1 по каждому лейблу, sweep порогов `tau_*`,
отчёт «токены и $ на 1000 колонок». Датасет и отчёты — в репозитории.

## 2. Что сделано

| Чанк | Результат |
|---|---|
| 6б-1 | `evalset.Read` — потоковое чтение `manifest.json` + `columns.jsonl` (формат — контракт ADR-impl-6а D5); round-trip и error-тесты |
| 6б-2 | Пакет `internal/evalharness`: `Run` — каскад слоёв 0–2 по колонкам датасета (слоёвой порядок и правила ансамбля зеркалят `scanengine.verdict`: meta по имени → rules → `ensemble.Decide` → при Escalate LLM-классификатор → пересборка → верификатор `ApplyVerifier`; small_sample → UNKNOWN/pending). Без store, аудита, кэша вердиктов, кластеризации и budget-стопа — детерминированный дешёвый контур (ADR-impl-6а D1). LLM-слой опционален: `nil` → слои 0+1 (CI без сети) |
| 6б-3 | Метрики: per-label P/R/F1 по truth-лейблу (спуфы участвуют как UNKNOWN — ADR-impl-6а D2), micro/macro F1, точность по видам колонок, **spoof-precision** по имитируемым лейблам («доля спуфов UNKNOWN, не отнесённых к X» — отдельной строкой, поскольку чексумма-спуфы формально UNKNOWN) |
| 6б-4 | Sweep `tau_accept` (сетка `-tau-grid от:шаг:до`, default 0.50:0.05:0.95): ансамбль переоценивается по закэшированным кандидатам слоёв 0–1 без LLM-вызовов. Без LLM лейбл инвариантен к tau (побеждает лучший кандидат) — sweep показывает trade-off «доля auto_accepted ↔ F1 на решённых» (F1_all, F1_decided, macro F1 в каждой строке) |
| 6б-5 | Экономика (п. 17): токены из `agentproxy.Usage` ok-вызовов, `$` по прайсу из флагов `-price-in/-price-out` ($/1M токенов; в контур store не входит — `model_prices` недоступен, прайс задаётся извне, нули = учёт без цены), нормировка «на 1000 колонок» |
| 6б-6 | Отчёт `Report` (схема semver 1.0.0): dataset+config refs, per-label, micro/macro, by_kind, spoofs, review_status, sweep, economics; **без wall-clock** — повторный прогон даёт побайтовый JSON (проверено `cmp`); `WriteReport` (mkdir -p, LF) + человекочитаемая `Text`-сводка. Закоммичен: `evals/reports/report.json` (бaseline слоёв 0+1 по датасету 1.0.0) |
| 6б-7 | `cmd/eval run`: флаги `-dataset/-taxonomy/-detectors/-out/-limit/-tau-grid`; `-llm` с `-agent/-endpoint/-price-in/-price-out` — прокси агента и верификатор (`escalate_to`) с общим Gate и egress-политикой, зеркало `buildLLMComposite` cmd/zond (п. 10.4, п. 10.7; fail-fast без ключа; `-endpoint` — для локального стенда/fake-LLM). `make eval` — прогон по закоммиченному датасету (регенерация — `eval generate`, она меняет `generated` в манифесте, поэтому вне цели) |
| 6б-8 | Тесты (7): ручной расчёт метрик по 6-колоночному датасету (включая честный урок: ИНН-10-спуф коллидирует с форматом паспорта — в тесте ИНН-12; в реальном датасете это видно в метриках), sweep-инвариантность F1_all и монотонность auto_accepted, fake-LLM эскалация (classify→verify confirm, учёт токенов/$, per-1000), ошибки вызова и small_sample, валидация tau, детерминизм сериализации отчёта, Text-сводка |

## 3. Ключевые решения

См. `docs/decisions/ADR-impl-stage-6b-evalharness.md`. Кратко:

- **Контур harness'а самостоятельный** (без store/аудита/кэша/кластеров):
  детерминированные дешёвые прогоны в CI; дублирование ~60 строк каскада
  принято осознанно, риск дивергенции с движком снижен общим пакетом
  `ensemble` и self-check'ами S6а.
- **Sweep без LLM**: перебор с LLM — повторные платные недетерминированные
  вызовы; LLM-режим отчитывается на конфигурированном tau отдельно.
- **Ground truth**: per-label метрики по `label` (спуфы=UNKNOWN),
  spoof-precision — отдельно (контракт ADR-impl-6а D2).

## 4. Baseline по датасету 1.0.0 (слоёв 0+1, tau_accept=0.80, отчёт закоммичен)

- Чексумма/regex-лейблы: BANK_ACCOUNT, IDENTIFIER, IP_ADDRESS F1=1.000;
  EMAIL 0.966, PHONE 0.810, SNILS 0.740, CARD_NUMBER 0.712, TAX_ID 0.649.
- Лейблы без recognizer'а (PERSON_NAME, ADDRESS, GEO_LOCATION, FREE_TEXT,
  NUMERIC_MEASURE, BOOLEAN, JSON_DOC, DATE_OF_BIRTH) — recall ≈ 0 без LLM:
  их различает только слой 2 (это и есть мотивация LLM-режима).
- Spoof-precision: BANK_ACCOUNT 1.000, TAX_ID 0.700, SNILS 0.167,
  CARD_NUMBER 0.000 (имена спуф-колонок `card_raw`/`pan_txt` бьют в слой 0
  по паттерну `card|pan` — честное измерение ложных срабатываний meta).
- micro F1=0.489, macro F1=0.468; auto_accepted 461/1000.
- Sweep: F1_all инвариантен (0.489), F1_decided растёт с tau
  (0.763 @0.50 → 0.831 @0.85) при падении доли автопринятых 490→408.

## 5. Проверки (протокол — docs/validation/2026-10-21-stage-6b.md)

- `go build`, `go vet`, `gofmt -l .` — чисто; `golangci-lint run` — 0 issues.
- `go test ./...` — все пакеты ok; `go test -race` новых пакетов — ok.
- `make ci`, `make config-check` — зелёные.
- Детерминизм отчёта: два прогона `make eval` → `cmp` побайтово совпал.
- LLM-режим против реального агента в этой сессии не гонялся (нет стенда):
  контур покрыт fake-тестами; прогон `-llm` — отдельной задачей при
  появлении эндпоинта.

## 6. Изменённые файлы

Новые: `internal/evalharness/{harness.go,metrics.go,harness_test.go}`,
`evals/reports/report.json`.
Изменённые: `internal/evalset/evalset.go` (+Read), `internal/evalset/evalset_test.go`
(+2 теста), `cmd/eval/main.go` (+run), `Makefile` (+eval).
go.mod не менялся. architecture.md — в «-док» коммите.

## 7. Не вошло (следующие инкременты)

- Прогон `-llm` против реального LLM-стенда с $-отчётом (п. 16.6) — когда
  появится доступный эндпоинт; CI-ворота на отчёт (п. 16.7) — отдельным решением.
- **S6в** — метрики и наблюдаемость (blueprint п. 17): expvar-экспозиция,
  алертинг событий, дашборды (частично есть в UI).
- Нагрузочный тест `make bench` (п. 16.8) — отдельной задачей.
