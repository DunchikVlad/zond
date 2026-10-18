# Архитектура системы `classifier` — модель реализации (v1)

Дата: 2026-10-17. Производный рабочий документ от `blueprint.md` (единственный
источник правды). Blueprint отвечает на «что строим и почему» (ADR, контракты,
DoD); этот документ — на «как устроено внутри и как строить»: слои, потоки
исполнения, процессная модель, карта пакетов, механизмы. При противоречии
действует `blueprint.md`, этот файл приводится в соответствие.

Статус: `READY FOR IMPLEMENTATION` (этап 0, blueprint п. 21).

---

## 1. Архитектурный стиль и принципы

**Стиль: модульный монолит — один Go-бинарник, слоистая организация пакетов,
порты-и-адаптеры в облегчённом виде** (ADR-0001, ADR-0006, ADR-0007).

Принципы, из которых выводится всё остальное:

1. **Компилируемый артефакт важнее распределённости.** Один бинарник
   `classifier`, весь runtime — внутри одного процесса; HA/multi-node сознательно
   вне скоупа (blueprint п. 15.1, п. 20).
2. **Ядро чистое, зависимости направлены внутрь.** Доменные пакеты не знают
   ни о БД, ни о HTTP, ни о LLM; адаптеры зависят от интерфейсов-портов,
   объявленных у потребителя (Go-идиома: интерфейс там, где используется).
3. **Конвенция путей вместо фреймворков плагинов.** Новая БД, recognizer,
   агент подключаются по конвенции (регистрация в `init()` + YAML), без правки
   ядра (blueprint п. 4, п. 12).
4. **Данные потоком, никогда целиком.** `iter.Seq2[Row, error]` от коннектора
   до вердикта; пул значений колонки ограничен `max_rows × max_string_chars`
   (blueprint п. 5.1, п. 13).
5. **Детерминизм конвейера.** Один и тот же вход даёт один и тот же вердикт:
   фиксированные правила ансамбля, tie-break, округление (blueprint п. 7).
6. **Безопасность через конструкцию**: изоляция LLM — один пакет; секреты —
   один резолвер; аудит — одна точка записи (ADR-0010/0012/0013).
7. **Конфигурация как API**: три YAML-файла со схемной валидацией и fail-fast
   (ADR-0009); горячая перезагрузка только `detectors.yaml` (ADR-0014).

---

## 2. Контекст системы (C4, уровень 1)

```
                        ┌──────────────────┐
                        │ Администратор/    │
                        │ ревьюер (браузер) │
                        └────────┬─────────┘
                                 │ HTTPS
              ┌──────────┐   ACS/   │          ┌───────────────────────┐
              │ Корпоративный │◀──SAML──▶│                     │ LLM-агенты            │
              │ IdP (Keycloak,│  SLO     │  classifier        │ (OpenAI-compatible:    │
              │ ADFS, Entra) │          │  (single binary,   │  внешние API / локаль- │
              └──────────┘          │   scan + serve)    │  ные Ollama, vLLM)    │
                                 │        │          └───────────▲───────────┘
              ┌──────────┐          │        │   только маскированные значения,
              │ HashiCorp   │──────────────▶│                     │  allowlist по умолч. пуст
              │ Vault (опц.)│  секреты БД  │        │                     │
              └──────────┘          │        │          ┌───────────┴───────────┐
                                 │        ▼          │ БД-источники (read-only):│
                          ┌──────┴───────┐          │ ClickHouse, MongoDB, …  │
                          │ SQLite (WAL) │◀─────────│ запросы сэмпла, ping    │
                          │ Verdict Store│          └─────────────────────────┘
                          └──────────────┘
                                 │ hash-chain аудит ▶ SIEM (syslog/CEF, опция)
```

Внешние сущности: администратор (UI/API), IdP (SAML 2.0), источники данных
(только чтение), LLM-эндпоинты (только маскированные значения), Vault (опция),
SIEM (опция). Всё остальное — внутри одного процесса.

---

## 3. Компонентная структура (C4, уровень 2)

```
cmd/classifier/          scan │ serve │ migrate │ eval │ seed │ agent-check
                         token │ audit │ backup │ doctor │ version
        │
        ▼
┌────────────────────────────────────────────────────────────────────────┐
│ internal/                                                              │
│                                                                        │
│  [domain] — чистое ядро, ноль внешних зависимостей                     │
│    verdict/        типы Verdict, Label, Sensitivity, review_status     │
│    taxonomy/       YAML-модель, semver, alias-маппинг, сгенер. константы│
│    analyze/rules/  движок recognizer'ов + checksum-валидаторы (порт)    │
│    analyze/meta/   слой 0: имена, словари, статистика                   │
│    fingerprint/    отпечаток колонки (п. 7.6 blueprint)                 │
│    ensemble/       фиксированные правила голосования, эскалация         │
│                                                                        │
│  [application] — оркестрация, порты (интерфейсы) объявлены здесь        │
│    scanengine/     конечный автомат скана, воркеры, чекпоинты, resume   │
│    agentproxy/     ЕДИНСТВЕННЫЙ вызов LLM: mask/, кэш, бюджет, лимиты   │
│    review/         очередь ревью, review_events                         │
│    drift/          сравнение сканов                                     │
│    scheduler/      cron-пересканы, окна сканирования, TTL-очистка       │
│                                                                        │
│  [infrastructure] — адаптеры к внешнему миру                            │
│    connector/      SPI + registry; clickhouse/, mongodb/, conftest/     │
│    sampler/        профили N/%, стратификация, дедуп, усечение          │
│    verdict/store/  SQLite (modernc, goose), единственный писатель       │
│    llmclient/      тонкий OpenAI-compatible клиент (только из agentproxy)│
│    auth/           SAML SP (crewjam), сессии, роли                      │
│    secrets/        Resolver: ENV | Vault kv-v2 | Vault dynamic          │
│    audit/          append-only + hash-chain + SIEM-sink                 │
│    logging/        JSON-логи, correlation id, redact                    │
│    observe/        agent_calls-учёт, expvar, OTel                       │
│                                                                        │
│  [api/web] — входные адаптеры                                           │
│    api/            REST handlers (chi), единый конверт ошибок           │
│    web/            html/template + HTMX (embed.FS), страницы UI         │
└────────────────────────────────────────────────────────────────────────┘
        ▲ вход                                ▼ хранение
   configs/*.yaml (connections │ detectors │ taxonomy)
```

**Правило зависимостей** (проверяется `depguard` в CI, blueprint п. 10.1):
`api/web → application → domain`; `infrastructure → application/domain`
(реализует порты). Запрещено: `domain → infrastructure`, импорт HTTP/SQL/LLM
из домена, вызов LLM вне `agentproxy` (литеральный бан-лист пакетов).

**Порты (интерфейсы), заявленные в application/domain:**

| Порт | Где объявлен | Реализации (infra) |
|---|---|---|
| `connector.Connector` (blueprint п. 5.1) | `connector/contract.go` | clickhouse, mongodb, `<db>` |
| Recognizer (analyze) | `analyze/rules/registry.go` | luhn, iban, inn, snils, … |
| `secrets.Resolver` (ADR-0012) | `secrets/` | env, vault-kv2, vault-dynamic |
| Store (Verdict Store) | `verdict/store/` (тонкий интерфейс) | sqlite сейчас, postgres v2+ (ADR-0006) |
| Masker | `agentproxy/mask/` | по типам значений (маск-профиль п. 10.2) |
| LLM endpoint | — | только через agentproxy (не порт наружу) |

---

## 4. Потоки исполнения

### 4.1. Скан: одна колонка через каскад

```
Sample (iter.Seq2) ──▶ статистика сэмпла (null/длина/уникальность)
   │
   ▼
[слой 0 meta] ─ сильное совпадение ──────────────┐
   │ нет                                         ▼
   ▼                                     [ensemble] ─▶ вердикт
[слой 1 rules] ─ checksum 0.99 ────────────▶ ─────┘   (таблица verdicts +
   │ нет                                                agent_calls, 1 tx)
   ▼
[кластеризация] ─ представитель уже классифицирован? ─▶ propagate (cluster_propagated=true)
   │ нет
   ▼
в серой зоне [0.30, 0.70] и сэмпл достаточен? ─ нет ─▶ UNKNOWN + pending (small_sample)
   │ да
   ▼
[agentproxy] mask → кэш? ─ hit ─▶ вердикт из кэша
   │ miss
   ▼
LLM-вызов (1 колонка = 1 сессия) → валидация JSON →
   ▼
[ensemble] tau_accept? → auto_accepted │ escalate_to? → верификатор → иначе pending
```

Колонка выбывает из пайплайна сразу, как только получен вердикт с достаточной
уверенностью (blueprint п. 1, п. 7). Кэш-попадание и распространение по кластеру
не делают LLM-вызова и не пишут `agent_calls` с `cached=0`.

### 4.2. Скан: состояния прогона

```
              ┌─────────── done (все таблицы ok)
              ├─────────── partial (таблицы failed; не overload)
   running ───┤
              ├─────────── budget_exceeded (cost_scan_limit_usd; остаток → pending)
              ├─────────── interrupted (cancel/shutdown → чекпоинт → --resume)
              └─────────── failed (старт невозможен: конфиг/источник целиком)

   переходы — транзакционно в scans.status (blueprint п. 13)
```

Оркестрация (`scanengine`): список таблиц → для каждой: schema → sampler →
поток колонок через каскад → пакетный commit вердиктов (чекпоинт после таблицы).
Воркеры: глобальный пул 4 на таблицы + семафор LLM 8; **поверх — лимиты
источника** (п. 13.2 blueprint): `max_concurrent_scans=1`, `max_concurrent_tables=2`,
таймаут запроса 5 мин, circuit breaker (5× `source_overload` → пауза 5 мин).

### 4.3. Ревью, дрейф, экспорт

- **Ревью**: карточка `pending` → действие confirm/reject/relabel → запись
  `review_events` (append-only) + смена `review_status` + аудит (SSO-личность).
  Bulk-действия — пакет той же операции.
- **Дрейф**: сравнение двух сканов одного источника с **одинаковым
  config_fingerprint**; новые/исчезнувшие пути, смена лейбла, Δconfidence ≥ 0.1
  (иначе шум; blueprint п. 11).
- **Экспорт**: фильтр → выгрузка ≤ `export_max_rows` (50 000) синхронно; больше —
  async-задача; событие в аудите (кто/скан/формат/строк).

---

## 5. Ключевые механизмы реализации

### 5.1. Agent Proxy (ядро ценности)

Один пакет — единственный, кто знает про LLM. Внутреннее устройство:

1. **Принимает** от пайплайна: нативный тип + пул значений + контекст решения
   (серый коридор, кандидаты ансамбля).
2. **Маскирование** `mask/`: профиль из `detectors.yaml` (версия — в ключе кэша);
   значения ≤4 символов исключаются из вызова (blueprint п. 10.2).
3. **Кэш**: ключ `sha256(agent|model|prompt_ver|taxonomy_ver|mask_ver|fingerprint)`
   → `verdict_cache`, TTL 30 дней, прочистка шедулером.
4. **Лимиты**: семафор 8, rate-limit rps, budget-стоп скана (`budget_exceeded`).
5. **Транспорт**: `llmclient` (net/http): OpenAI-compatible chat completions,
   `response_format: json_schema`, backoff 1→2→4 с + jitter, repair-retry на
   не-JSON, далее `llm_unavailable` → UNKNOWN + pending.
6. **Egress-политика**: allowlist по умолчанию пуст → loopback/RFC 1918 только;
   `offline: true` запрещает внешнее. Закрывает SSRF.
7. **Учёт**: каждый вызов → `agent_calls` в той же транзакции, что и вердикт
   (нет висящих вердиктов без учёта).

### 5.2. Ensemble

Фиксированные правила + псевдокод — blueprint п. 7 (применять как есть):
checksum побеждает; `score[l]=Σ(w·c)`; `tau_accept=0.80`, отрыв ≥0.3;
верификатор +0.1 (cap 0.95); иначе `pending`. Веса — конфигурируемы, но не
«обучаются» в MVP. Все входы округления — до 4 знаков; tie-break — лексико-
графически меньший лейбл. Никакой непрозрачности: в `evidence` пишутся вклады
слоёв (`per_layer: {meta: {label, c}, rules: …, llm: …}`).

### 5.3. Кластеризация

До слоя 2: fingerprint (нативный тип + классы значений + длины + null +
уникальность + энтропия + префикс/суффикс по маскированным значениям),
порог 80% признаков, кластер ≤100, mixed-типы не кластеризуются (blueprint
п. 7.6). Реализация — чистая функция в `fingerprint/`, тест на стабильность.

### 5.4. Verdict Store и процессная модель

- SQLite (modernc, чистый Go), `PRAGMA journal_mode=WAL`, `busy_timeout=5000`,
  `foreign_keys=ON`; миграции goose, embed в бинарник (blueprint п. 11.1).
- **Единственный писатель** — внутренняя очередь (канал + один writer-goroutine):
  скан пишет вердикты/чекпоинты, аудит — свои записи; UI читает напрямую (WAL
  даёт читателей без блокировки записи). Это снимает `SQLITE_BUSY` и гонки.
- Таблицы и индексы — blueprint п. 11.1 (включая `audit_log`, `api_tokens`).
- `classifier backup`: `VACUUM INTO` на живой БД; учебное восстановление в DoD
  (blueprint п. 15.2).

### 5.5. Аудит (hash-chain)

Каждое действие UI/API/CLI/агента → `audit_log` (INSERT-only, код + триггер
миграции). Каноническая форма: UTF-8 JSON с сортированными ключами над полями
`seq,ts,actor,category,action,target,details_json`, терминатор `\n`;
`entry_hash=sha256(prev_hash|canonical)` в той же транзакции; писатель под
mutex. Внешний sink: syslog/CEF с локальной очередью повторов (blueprint п. 14.2).

### 5.6. Конфигурация и секреты

Три файла (ADR-0009): `connections.yaml` (источники + sso + vault, секретов нет),
`detectors.yaml` (правила/агенты/пороги/маск-профиль — **hot-reload**, watch +
«Применить», бамп `detectors_version`, аудит с diff), `taxonomy.yaml` (semver,
генерация Go-констант на `go generate`). Секреты: `${ENV}`-интерполяция или
`secrets.Resolver` (Vault kv-v2 / dynamic leases, лизы продлевает фоновая
горутина, в памяти только; blueprint п. 12.1). Fail-fast на старте с перечнем
проблем.

### 5.7. Аутентификация и авторизация

SAML 2.0 SP (`crewjam/saml`): metadata SP/IdP, ACS/SSO/SLO, Signed/Encrypted
assertions, anti-replay (InResponseTo, skew ≤60 с), JIT → `users`, роли
admin/viewer из атрибута/групп (максимальная при конфликте). Сессии в памяти
(рестарт разлогинивает — допустимо для single-instance). API-токены: argon2-хэш,
scope, TTL 90 дней, мгновенный отзыв, `last_used_at`. Матрица доступа —
blueprint п. 11.3. Admin-токен — bootstrap/аварийный fallback, rate-limit +
warn-аудит, в штате выключен.

---

## 6. Процессная модель и конкурентность

```
serve (1 процесс)
├─ HTTP-сервер (chi): API + web UI
├─ SSO/session middleware
├─ scheduler (cron): пересканы, окна сканирования, TTL-очистка cache
├─ audit writer (1 goroutine, mutex, hash-chain)
├─ config watcher (detectors.yaml hot-reload)
├─ secrets renewer (Vault leases)
└─ scan workers (по запросу API/CLI/шедулера)
     ├─ table pool (4) → per-source caps (1 scan / 2 tables)
     ├─ per-column pipeline (слои 0→1→кластер→proxy→ensemble)
     ├─ llm semaphore (8) + rate-limiter + budget-учёт
     └─ verdict writer → очередь писателя SQLite
```

- Отмена: `context.Context` от корня (HTTP-запрос/CLI/shutdown) до коннектора
  и LLM-вызова; graceful shutdown доводит LLM-вызовы до retry-safe точки.
- Идемпотентность: `verdicts.id = sha1(scan_id|table|path)` — повторная вставка
  заменяет; повторный скан = новый `scan_id`, старые вердикты в истории.
- Resume: только при совпадении `config_fingerprint` + `taxonomy_version` +
  версии бинарника (иначе отказ, код 2; blueprint п. 6, п. 13).

---

## 7. Карта пакетов → ответственность (для этапа 0)

| Пакет | Ответственность | Ключевые типы |
|---|---|---|
| `cmd/classifier` | подкоманды, wiring (конструирование графа) | main, subcommand funcs |
| `internal/config` | загрузка/валидация 3 YAML, ${ENV}-интерполяция, fingerprint | Config, Validator |
| `internal/connector` | SPI + registry + conftest | Connector, TableRef, SampleSpec |
| `internal/connector/clickhouse` | системные таблицы, SAMPLE/rand, сложные типы | clickhouseConnector |
| `internal/connector/mongodb` | $sample, flatten, полиморфизм | mongoConnector, flattener |
| `internal/sampler` | профили, стратификация, дедуп, усечение | Sampler, Profile |
| `internal/analyze/meta` | слой 0 | MetaAnalyzer |
| `internal/analyze/rules` | движок recognizer'ов, checksum | Recognizer, Registry, Match |
| `internal/analyze/cluster` | группировка по fingerprint | Clusterer |
| `internal/fingerprint` | отпечаток колонки | Fingerprint, FeatureSet |
| `internal/agentproxy` | изоляция/маск/кэш/лимиты/бюджет | Proxy, Masker, Cache, Semaphore |
| `internal/agentproxy/prompts` | промпты vN (embed.FS) | — |
| `internal/ensemble` | правила голосования, эскалация | Ensemble, VerdictBuilder |
| `internal/verdict` (+`/store` `/drift`) | домен вердикта, SQLite, дрейф | Verdict, Store, DriftComparer |
| `internal/scanengine` | FSM скана, воркеры, чекпоинты | Engine, ScanFSM, Checkpoint |
| `internal/auth` | SAML SP, сессии, роли | SP, SessionStore, RBAC |
| `internal/api` / `internal/web` | REST, UI | Handlers, Templates |
| `internal/secrets` | Resolver ENV/Vault | Resolver, LeaseManager |
| `internal/audit` | hash-chain, sink | Auditor, Chain |
| `internal/logging` | JSON-лог, correlation id, redact | Logger, Redactor |
| `internal/observe` | agent_calls-учёт, expvar, OTel | Meter, Tracer |
| `internal/scheduler` | cron, окна, TTL-jobs | Scheduler |
| `evals/`, `cmd/seed` | датасет, отчёты, демо-данные | Generator |

---

## 8. Технологическая карта

Сводка из blueprint п. 3 (детали и версии — там): clickhouse-go/v2,
mongo-driver, modernc.org/sqlite (чистый Go — кросс-сборка без cgo),
goose/v3 (embed), chi/v5, crewjam/saml, hashicorp/vault/api, lumberjack,
yaml.v3, net/http (свой LLM-клиент), cenkalti/backoff/v5, robfig/cron/v3;
тесты: testify, go-cmp, testcontainers-go (+CH/Mongo); CI: golangci-lint
(depguard-правила зависимостей слоёв), go-licenses, govulncheck, syft.

Правило выбора зависимостей: только pure-Go (кроме драйверов БД, которые и так
pure-Go), MIT/BSD/Apache-2.0, без обязательных внешних демонов — air-gapped
из коробки (blueprint п. 15).

---

## 9. Точки расширения (как расти без переписывания)

| Задача | Что делается | Чего НЕ трогаем |
|---|---|---|
| Новая БД | `internal/connector/<db>/` + `init()`-регистрация + conftest-профиль | ядро, scanengine |
| Новый recognizer | файл в `analyze/rules/` + запись в `detectors.yaml` + золотые вектора | движок, прокси |
| Новый агент | блок в `detectors.yaml` (endpoint/model/лимиты/band/escalate) | код |
| Новый лейбл | `taxonomy.yaml` + minor bump; prompt/UI/eval синхронизируются (go generate) | схема БД (лейблы — строки) |
| Смена порогов/весов | `detectors.yaml`, hot-reload, аудит с diff | рестарт, миграции |
| PostgreSQL-хранилище | реализация порта Store (ADR-0006) | домен, API |
| Локальный NER v2 | новый «слой» перед LLM за тем же интерфейсом вызова | agentproxy, каскад |

---

## 10. Кросс-cutting concerns (где живут)

- **Безопасность**: маскирование evidence (ADR-0010) — `agentproxy`+store;
  SSO/RBAC — `auth`; аудит — `audit`; секреты — `secrets`; egress-политика —
  `agentproxy`; XSS/CSP/CSRF — `web`/middleware. Полная матрица угроз —
  blueprint п. 14.
- **Наблюдаемость**: учёт токенов/$ — `observe`→`agent_calls`; метрики —
  expvar/OTel; алертинг — события + SIEM-sink; дашборды — `/scans/{id}`, `/cost`.
- **Ошибки**: единая таблица поведения — blueprint п. 6 (ретраи, чекпоинты,
  circuit breaker); ошибки API — единый конверт.
- **Трассировка решения**: `evidence` + `agent_calls` + correlation id связывают
  UI-запрос → скан → колонку → вызов агента → вердикт → ревью.

---

## 11. Деплой-архитектура

- **Dev/demo**: `deploy/docker-compose.yml` — app + CH + Mongo + seed +
  Keycloak; `make smoke` ≤15 мин до первых вердиктов (blueprint п. 24).
- **Prod**: один бинарник как systemd-unit или scratch-контейнер (non-root,
  read-only FS), SQLite на смонтированном томе, reverse-proxy с TLS; секреты
  env/Vault; backup по расписанию (п. 15.2); `doctor --strict` на старте.
- **Air-gapped**: вся статика embed, HTMX vendored, LLM локальный, OTLP off.

### 11.1 Что улучшить перед реализацией

1. **Явно описать SLA/SLO**: сейчас есть NFR, но нет целевых SLO по `serve`
   (доступность UI/API, допустимое время деградации LLM, целевое время resume).
2. **Выделить runbook-пакет документации**: архитектура уже учитывает backup,
   doctor, audit, но для прод-эксплуатации нужны короткие сценарии реагирования.
3. **Зафиксировать стратегию API-версирования**: `/api/v1` уже есть, но правило
   совместимости лучше считать архитектурным контрактом, а не только частью blueprint.
4. **Подготовить путь к роли `reviewer`**: даже если в MVP остаются `admin/viewer`,
   пакеты `auth`, `api`, `web` лучше не «зашивать» под два значения enum.
5. **Определить policy для long-running scans**: максимальная длительность,
   auto-stop, auto-resume после рестарта, поведение при смене `detectors.yaml` во
   время активного скана.
6. **Спроектировать provenance first-class**: версия конфигов, таксономии,
   prompt'ов, бинарника и коннектора должна проходить через весь pipeline как
   обязательный контекст, а не собираться постфактум.

---

## 12. Анти-архитектура (соглашение «что не делаем»)

1. Не выносить интерфейсы «на будущее» сверх портов из п. 3 — YAGNI, два разработчика.
2. Не вводить ORM, генераторы SQL, репозитории-абстракции — sql + goose напрямую.
3. Не добавлять batch-LLM, многоходовые сессии агентов, обучаемые веса ансамбля в MVP (ADR-0005, п. 7).
4. Не читать таблицу/коллекцию целиком в память — только стримы с лимитами.
5. Не хранить и не логировать сырые значения нигде, включая трейсы (ADR-0010, п. 14.1).
6. Не тащить cgo, service mesh, брокеры сообщений, k8s-операторы — single binary.
7. Не строить SPA/фронтенд-сборку (ADR-0007), англоязычный UI (п. 20).
8. Не усложнять миграции: только forward-up в релизах; down — для dev-тестов (п. 16.9).
9. Не расширять таксономию без semver и alias-маппинга (п. 5.5).
10. Не смягчать изоляцию LLM «для удобства отладки» — дебаг через fake-LLM и `agent-check`.

---

## 13. Traceability: этапы разработки → пакеты

| Этап (blueprint п. 21) | Основные пакеты | Вертикальный результат |
|---|---|---|
| 0. Скелет (1 нед) | cmd, config, connector (SPI), logging, Makefile/CI | `classifier version`, валидный конфиг |
| 1. Вертикальный срез (1.5 нед) | connector/clickhouse, sampler, analyze/meta+rules (email/phone/INN/Luhn), verdict/store | scan CH → консольный отчёт |
| 2. Mongo (1.5–2 нед) | connector/mongodb, conftest | обе БД через один SPI, контракт-тесты зелёные |
| 3. Regex-слой (1.5–2 нед) | analyze/rules полный, fingerprint | RU-матчеры + золотые вектора, кластеризация |
| 4. LLM-слой (3 нед) | agentproxy (+mask, cache), ensemble, llmclient, observe | каскад 0→1→2→ensemble, изоляция подтверждена тестами |
| 5. Store+API+UI+SSO+аудит (3.5 нед) | verdict/store, api, web, auth, audit, secrets (env) | UI end-to-end, SSO через Keycloak, /audit |
| 6. Качество (1.5–2 нед) | evals, observe, cmd/seed | F1-отчёты, sweep порогов, $/1000 колонок |
| 7. Харденинг (1.5 нед) | secrets (vault), backup, doctor, деплой | релиз v0.1: подписан, документирован, DoD закрыт |

---

## 14. Связь с blueprint

| Раздел blueprint | Что здесь |
|---|---|
| п. 2 (ADR-0001–0014) | принципы п. 1, процессная модель п. 6, деплой п. 11 |
| п. 4–5 | карта пакетов п. 7, порты п. 3 |
| п. 6–7 | потоки п. 4, механизмы п. 5.2–5.3 |
| п. 8–9 | адаптеры п. 7, resource governance п. 4.2/п. 6 |
| п. 10 | механизм п. 5.1 |
| п. 11–12 | п. 5.4–5.7, RBAC/хот-релоад |
| п. 13–15 | п. 4.2, 6, 11 |
| п. 16, 18 | п. 12 (traceability), NFR-реализация (bench — п. 16.8 blueprint) |
| п. 20–22 | анти-архитектура п. 12, скоуп п. 11, DoD — там |

Изменения только в `blueprint.md`; этот документ обновляется следом.

Практическое следствие: если появляется новая функциональная или эксплуатационная
идея, сначала фиксируем её как изменение контракта/ADR/NFR в `blueprint.md`, и
только потом отражаем в слоях, пакетах и потоках этого документа.
