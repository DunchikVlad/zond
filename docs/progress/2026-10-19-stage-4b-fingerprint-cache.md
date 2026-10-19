# Прогресс: этап 4, инкремент 4б — fingerprint + кластеризация + кэш вердиктов

Дата: 2026-10-19
Исполнитель: Coordinator / Stage 4 (инкремент б)
Статус: **done**

## 1. Цель

Закрыть экономику LLM-слоя (blueprint п. 21, этап 4; риск R2): отпечаток
колонки (п. 7.6) → кластеризация до слоя 2 → кэш вердиктов LLM (п. 10.5).

## 2. Что сделано

| Чанк | Результат |
|---|---|
| 4б-2 | `internal/fingerprint`: FeatureSet (нативный тип; доминирующий класс digit/alpha/mixed/empty; min/avg/max длина; доля null; уникальность; энтропия Шеннона по ≤1000 значений; префикс/суффикс 2 по маскированным значениям), bucketized `Similarity` (9 признаков), `ID` (sha256[8] канонической строки), `ValuesHash` (sha256 отсортированных уникальных усечённых значений, п. 10.5) |
| 4б-3 | Миграция `0002_verdict_cache.sql` (таблица + индекс по expires_at); store: `CacheGet` (только непросроченные), `CachePut` (upsert), `CachePurgeExpired` (п. 15.4); TTL default 30 дней (`CacheTTLDefault`) |
| 4б-4 | `internal/analyze/cluster`: Clusterer (similarity default 0.8, maxSize default 100); mixed/пустой тип не кластеризуются (п. 7.6, п. 8); полный кластер не пополняется — новая колонка дробит (id суффикс `#n`, упрощение «дробление по энтропии»); `Verdict`/`SetVerdict` для propagation |
| 4б-5 | Wiring в scanengine: отпечаток по маскированным значениям до слоя 2; член кластера с вердиктом представителя получает копию без LLM-вызова (`evidence.cluster_propagated=true`, `verdicts.cluster_id`); LLM-серый коридор идёт через кэш: ключ = sha256(scope=agent\|model, prompt, taxonomy, mask-версия, valuesHash), hit → вердикт без вызова, miss → вызов + запись; счётчики экономики в Report/Text/stats_json (п. 17) |
| 4б-6 | Тесты: fingerprint (детерминизм, ValuesHash порядко-независим, similarity пороги, классы), cluster (register/find, mixed-исключение, maxSize-дробление, propagation), store-cache (round-trip, TTL-miss, purge), engine E2E (propagation: 1 LLM-вызов на 2 колонки; кэш между сканами: 2-й скан без вызовов; Clustering-выключен по умолчанию) |

## 3. Ключевые решения

- Кэш хранит только {label, confidence, prompt_version} — без значений
  (ADR-0010). Ключ включает версии prompt/taxonomy/mask — смена любой
  инвалидирует естественно (п. 10.5).
- Отпечаток считается по маскированным значениям (mask.Mask) — префиксы/
  суффиксы не утекают в кластеризацию (п. 7.6).
- Кластеризация по скану: Clusterer создаётся на каждый Scan (представитель —
  первая по порядку колонка скана); не путается между прогонами.
- `CacheScope` в Config = `agent_id|model`; кэш выключен при "" — поведение
  прежних тестов/прогонов без LLM не изменилось.
- Дробление полного кластера — новым id `#n` вместо «по энтропии» (п. 7.6
  формулирует дробление по энтропии; эмпирически редкий случай, см.
  упрощения в ADR-impl-stage-4 при обновлении).
- Verify (верификатор) кэшем не покрывается — только Classify.

## 4. Проверки (протокол — docs/validation/2026-10-19-stage-4b.md)

- `go build`, `go vet`, `gofmt` — чисто; `golangci-lint` — 0 issues.
- `go test ./...` — все пакеты ok; `go test -race ./internal/...` — 15 ok.
- `zond config validate` — OK (блок cluster в detectors.yaml принят).
- E2E: propagation (2 одинаковые колонки → 1 LLM-вызов), кэш между сканами
  (2-й скан → 0 вызовов, cacheHits=1).

## 5. Изменённые файлы

`internal/fingerprint/*`, `internal/analyze/cluster/*`,
`internal/verdict/store/{cache.go,cache_test.go,migrations/0002_*}`
`internal/scanengine/{engine.go,cache_cluster_test.go}`,
`internal/config/config.go` (ClusterConfig + валидация), `configs/detectors.yaml`,
`cmd/zond/main.go` (wiring).

## 6. Не вошло (инкремент 4в, blueprint п. 10)

- `agent_calls` (п. 10.6): учёт токенов/стоимости/латентности в транзакции
  с вердиктом — миграция + proxy-учёт.
- Лимиты/бюджет (п. 10.4): семафор конкурентных вызовов, rate-limit,
  budget-стоп `budget_exceeded`.
- Egress/контур (п. 10.7): allowlist (loopback/RFC 1918 по умолчанию),
  флаг `offline`, локальные эндпоинты.

## 7. Следующие шаги

1. Инкремент 4в (agent_calls + лимиты + egress) — завершает слой 2.
2. Этап 5: Store + API + веб-UI + SSO + аудит.
