# Классификатор данных в БД — blueprint к разработке (v2)

Дата: 2026-10-17. **Единственный источник правды.** Заменяет аналитические документы,
перенесённые в `./анализ` (blueprint v1, decomposition.md, oss-reuse-analysis.md,
commercial-landscape.md) — те файлы носят исторический характер, решения приняты
здесь. Язык реализации — **Go**, анализ результатов — **веб-интерфейс**, встроенный
в единый бинарник.

Статус документа: `APPROVED FOR DEVELOPMENT`. Изменения — через PR с записью в
разделе «Changelog» (п. 25).

Производный рабочий документ — `architecture.md`: модель реализации
(слои, потоки исполнения, карта пакетов, механизмы). При противоречии
действует этот файл.

---

## 1. Постановка задачи

Система автоматического определения (классификации) данных в БД:

- Плагинные коннекторы к БД; первые — **ClickHouse** и **MongoDB**. Новая БД = один
  файл по конвенции пути, без правки ядра.
- Настраиваемый сэмпл: **N строк** или **p%**, с min/max-порогами и профилями
  («быстрый разведочный» / «глубокий»).
- Каскад анализа возрастающей стоимости: метаданные → regex+checksum → LLM-агенты
  → ансамбль/эскалация. Колонка выбывает из пайплайна, как только набрана
  достаточная уверенность.
- Агенты изолированы: единственная точка вызова LLM — Agent Proxy; агент получает
  только маскированные значения, без имён БД/таблиц/хостов; одна колонка = один
  вызов = новая сессия.
- Промпт — на английском, обоснование вердикта (`reason_ru`) — на русском.
- Приоритеты: **максимальная точность** + **максимальная экономия токенов**.
- Результат просматривается и разбирается в **веб-интерфейсе**: очередь ручного
  ревью, дрейф схемы, экономика сканирования, экспорт.
- Регуляторный контекст: целевая рамка — **152-ФЗ (ПДн, РФ)**; для контуров с
  ПДн предусмотрен полностью локальный режим (LLM на собственном эндпоинте,
  п. 10.7) и air-gapped-установка (п. 15).

## 2. Ключевые решения (сводка ADR)

Сформулированы как Architecture Decision Records; при противоречии с анализом
в `./анализ` действует этот раздел.

| # | Решение | Суть | Последствия |
|---|---|---|---|
| ADR-0001 | **Go 1.24, single binary** | Один бинарник `zond` со встроенным веб-UI (embed.FS), без внешних runtime-зависимостей | Отказ от Python-экосистемы (см. ADR-0002/0003); простой деплой, air-gapped-режим из коробки |
| ADR-0002 | **Свой regex-движок слоя 1** | Вместо Python-библиотеки Presidio — собственный движок recognizer'ов; RU-матчеры (ИНН, СНИЛС, паспорт, счета) **портируем** из angryscan-core (Apache-2.0, NOTICE обязателен); Luhn/IBAN/email/IP — пишем по спецификациям | Этап regex-слоя растёт с ~3 дней до ~1,5–2 нед; полный контроль над форматом, ноль Python-зависимостей |
| ADR-0003 | **Локальный NER-слой — в v2, не в MVP** | GLiNER/Piiranha — Python-модели; в Go нет zero-shot NER приемлемого качества. В MVP каскад: слой 0 (метаданные) → слой 1 (regex) → слой 2 (LLM). v2: ONNX-runtime sidecar с GLiNER между regex и LLM | В MVP больше колонок доходит до LLM — компенсируем кластеризацией, жёсткими порогами и кэшем (п. 10) |
| ADR-0004 | **Таксономия как код** | Список лейблов и enum чувствительности — версионируемые артефакты (`internal/taxonomy/taxonomy.yaml` + сгенерированные Go-константы, semver) | Промпт, ансамбль, API и UI говорят на одном языке; смена версии таксономии инвалидирует кэш |
| ADR-0005 | **Одна колонка = один вызов LLM; батчинг отклонён для MVP** | Пакетная отправка нескольких колонок конфликтует с изоляцией «новая сессия на колонку». В MVP — строго по одной колонке на вызов; batch-режим с изолированными «конвертами» — опция v2 при экономической необходимости | Нет противоречия изоляции; экономия достигается отсевом слоями 0–1, кластеризацией, кэшем |
| ADR-0006 | **SQLite-first Verdict Store** | `modernc.org/sqlite` (чистый Go, без cgo), миграции goose, встрачиваемые в бинарник. PostgreSQL — поддержка позже через слой хранилища | Один артефакт на установку; шифрование at rest — на уровне ФС/диска (п. 14) |
| ADR-0007 | **Веб-UI без отдельного фронтенда** | Серверный рендеринг `html/template` + HTMX (vendored, без CDN), статика в embed.FS. API — JSON REST тот же, что потребляет UI | Один бинарник, работа в air-gapped; SPA-фронтенд возможен позже поверх того же REST API |
| ADR-0008 | **Наблюдаемость: свой учёт + OTel** | Все вызовы агентов пишутся в таблицу `agent_calls` (токены, стоимость, латентность, версия промпта). Трассировка — OpenTelemetry (gRPC/HTTP OTLP), Langfuse опционально как OTLP-приёмник | Нет обязательного тяжёлого Langfuse-контура в MVP; экономика видна в UI «Качество и стоимость» |
| ADR-0009 | **Конфиг: YAML + переменные окружения для секретов** | `connections` и `detectors` — разные файлы (паттерн Hawk-Eye, только идея, код не копируем — лицензия). Секреты — только `${ENV}`-интерполяция или docker secrets | Чёткий контракт конфигурации, проверяемый схемой (п. 12) |
| ADR-0010 | **Evidence в БД только в маскированном виде** | В Verdict Store попадают только замаскированные примеры значений (`4***1234`), никогда сырые | Снижаем ценность БД для атакующего; обязательная маскированная выдача и в UI |
| ADR-0011 | **SSO SAML 2.0 в веб-UI** | Встроенная интеграция SAML 2.0 Service Provider (`crewjam/saml`): вход через корпоративный IdP (Keycloak, ADFS, Entra ID и пр.), Signed/Encrypted assertions, SLO. Роли `admin`/`viewer` маппятся из SAML-атрибута или групп; JIT-прvisioning пользователей. Админ-токен — только bootstrap и аварийный fallback | Аудит ревью привязывается к корпоративной личности; собственный user management не строим; отдельный фронтенд-прокси для SSO не нужен |
| ADR-0012 | **Vault: секреты БД без хранения на сервере (опция)** | Поддержка HashiCorp Vault как источника секретов подключений: динамические секреты (`database/creds/...` — короткоживущие лизы, авто-ротация и продление) или kv-v2 (чтение по пути в момент установки коннекта). Секрет не материализуется в конфиге, на диске и в ENV; живёт только в памяти на время жизни лизы | Для контуров с Vault — нулевое постоянное хранение секретов и автоматическая ротация; без Vault — прежний режим `${ENV}` (dev/air-gapped); пакет `internal/secrets` с интерфейсом `Resolver` (ENV | Vault kv-v2 | Vault dynamic) |
| ADR-0013 | **Все действия журналируются: два канала** | (1) Операционные логи: structured JSON, уровни, correlation id, ротация, обязательный redact секретов и PII перед записью. (2) Security audit log: append-only журнал всех действий — SSO-входы/неудачи, использование admin-токена, ревью-решения, старт/стоп/резюм сканов, изменения конфигов и реестра агентов, экспорт, вызовы агента (версия промпта, кэш, исход); цепочка хэшей против подмены; опциональный внешний sink в SIEM (syslog/CEF) | Ответственность «кто, что, когда, с каким результатом» закрыта для UI, REST API, CLI и агентных вызовов; пакет `internal/audit`, таблица `audit_log`; страница `/audit` в UI |
| ADR-0014 | **Эксплуатационная модель: single-instance + WAL + горячая перезагрузка конфигов** | Один процесс `serve` (API+UI+шедулер+встроенные сканы) на один инстанс; SQLite в WAL с `busy_timeout`, единственный писатель — через внутреннюю очередь; HA/multi-node — вне скоупа (п. 20). `detectors.yaml` (правила, агенты, пороги) перечитывается без рестарта: watch файла + «Применить» в `/settings`, валидация схемы, бамп `detectors_version`, событие в аудит с diff; при ошибке валидации действует прежняя версия. `connections.yaml` и блок `sso:` — только рестарт | Смена детекторов/агентов без даунтайма; предсказуемая конкурентность без распределённых блокировок; вне скоупа — multi-node (путь: PostgreSQL-хранилище, ADR-0006) |

## 3. Стек и зависимости

Go **1.24** (минимум 1.23 — итераторы `iter.Seq2`). Модуль: `github.com/DunchikVlad/zond`
(рабочее имя артефакта — `zond`, переименование — механическая замена).

| Назначение | Модуль | Примечание |
|---|---|---|
| ClickHouse | `github.com/ClickHouse/clickhouse-go/v2` | нативный протокол |
| MongoDB | `go.mongodb.org/mongo-driver` | официальный драйвер |
| SQLite | `modernc.org/sqlite` | чистый Go, нет cgo |
| Миграции | `github.com/pressly/goose/v3` | миграции embed-ятся в бинарник |
| HTTP-роутер | `github.com/go-chi/chi/v5` | + stdlib middleware |
| SSO/SAML 2.0 | `github.com/crewjam/saml` | Service Provider: метаданные, ACS/SSO/SLO, подпись и шифрование assertions |
| Секреты (Vault, опция) | `github.com/hashicorp/vault/api` | kv-v2 и динамические секреты БД, продление лиз фоновой горутиной (ADR-0012) |
| Ротация логов | `gopkg.in/natefinch/lumberjack.v2` | size-based ротация файловых логов |
| YAML-конфиг | `gopkg.in/yaml.v3` | схема валидируется руками (struct tags) |
| LLM-клиент | `net/http` (свой тонкий клиент) | OpenAI-compatible chat completions, `response_format: json_schema` |
| Ретраи/backoff | `github.com/cenkalti/backoff/v5` | экспонента + jitter |
| Расписание пересканов | `github.com/robfig/cron/v3` | встроенный шедулер |
| Тесты | `testify`, `go-cmp`, `testcontainers-go` (+ модули clickhouse, mongo) | контрактные и изоляционные тесты |
| Линт | `golangci-lint` | конфиг в репозитории |
| Лицензии зависимостей | `github.com/google/go-licenses` | проверка в CI |
| Метрики runtime | `expvar` (+ опционально Prometheus endpoint) | |

## 4. Структура репозитория

```
zond/
├── cmd/
│   ├── zond/            # main: подкоманды scan | serve | migrate | eval | seed | agent-check
│   └── seed/                  # генератор демо-данных CH/Mongo (Faker-аналог на Go)
├── internal/
│   ├── config/                # загрузка/валидация YAML, ${ENV}-интерполяция секретов
│   ├── connector/             # SPI + реестр (загрузка по конвенции путей)
│   │   ├── contract.go        # интерфейс DbConnector, типы TableRef/Column/Row
│   │   ├── registry.go        # регистрация: имя → конструктор
│   │   ├── conftest/          # общий набор контрактных тестов для всех коннекторов
│   │   ├── clickhouse/        # connector.go, sampler_sql.go, types.go
│   │   └── mongodb/           # connector.go, flatten.go, sampler.go
│   ├── sampler/               # профили N/%, стратификация, min/max, дедуп, усечение
│   ├── fingerprint/           # отпечаток колонки и сэмпла (кластеризация, кэш)
│   ├── analyze/
│   │   ├── meta/              # слой 0: regex имён + словарь синонимов (RU/EN) + статистика
│   │   ├── rules/             # слой 1: движок recognizer'ов, checksum-валидаторы
│   │   │   ├── registry.go    # регистрация recognizer'ов
│   │   │   ├── luhn.go, iban.go, inn.go, snils.go, passport_rf.go, account_rf.go, ip.go, dates.go
│   │   │   └── vectors_test.go# золотые вектора (валидные/невалидные контрольные суммы)
│   │   └── cluster/           # кластеризация колонок по отпечатку (Cyera)
│   ├── agentproxy/            # единственная точка вызова LLM
│   │   ├── proxy.go           # изоляция, маскирование, лимиты, кэш
│   │   ├── mask/              # маскировщики по типам значений
│   │   ├── registry.go        # YAML-реестр агентов
│   │   └── prompts/           # версионируемые промпты (embed.FS): v1/*.txt
│   ├── ensemble/              # голосование слоёв, эскалация, пороги
│   ├── verdict/
│   │   ├── model.go           # типы Verdict, Label, Sensitivity
│   │   ├── store/             # sqlite store, миграции goose (embed)
│   │   └── drift/             # сравнение сканов, детект дрейфа схемы
│   ├── auth/                  # SSO SAML 2.0 SP: saml.go, session.go, roles.go (ADR-0011)
│   ├── api/                   # REST handlers (chi)
│   ├── web/                   # UI: handlers, templates, HTMX, статика (embed.FS)
│   ├── observe/               # учёт токенов/стоимости, OTel-трейсинг, expvar
│   ├── logging/               # structured JSON-логи: уровни, correlation id, redact (ADR-0013)
│   ├── audit/                 # append-only аудит действий + hash-chain + SIEM-sink (ADR-0013)
│   ├── secrets/               # резолвер секретов: ENV | Vault kv-v2 | Vault dynamic (ADR-0012)
│   └── scheduler/             # периодические пересканы
├── configs/
│   ├── connections.yaml       # профили подключений (без секретов)
│   ├── detectors.yaml         # правила слоёв 0–1, пороги, агенты
│   └── taxonomy.yaml          # лейблы, чувствительность, словари (ADR-0004)
├── evals/                     # генератор эталонного датасета, разметка, отчёты F1
├── deploy/
│   └── docker-compose.yml     # dev/demo: app + CH + Mongo + seed (make smoke)
├── migrations/                # SQL-миграции goose
└── Makefile                   # build / test / lint / smoke / eval
```

Конвенция подключения новой БД (ADR: «положил файл = подключил»): реализация
`internal/connector/<db>/connector.go` с `func init() { connector.Register("<db>", New) }`
+ указание `<db>` в конфиге сканирования. Ядро не меняется.

## 5. Контракты как код

### 5.1 SPI коннектора

```go
package connector

type TableRef struct{ Schema, Name string }
type Column struct {
    Name       string
    NativeType string // нативный тип БД, как строка
    Ordinal    int
}
type Row map[string]any // ключ — имя колонки / путь поля (Mongo)

type SampleMode int
const (
    SampleRows SampleMode = iota   // ровно N строк
    SamplePercent                  // p% (0<p<=100)
)

type SampleSpec struct {
    Table   TableRef
    Mode    SampleMode
    Value   float64  // N или p%
    Columns []string // nil = все
    MaxRows int64    // жёсткий предохранитель, по умолчанию 100_000
}

type Connector interface {
    Ping(ctx context.Context) error
    ListTables(ctx context.Context) ([]TableRef, error)
    GetSchema(ctx context.Context, t TableRef) ([]Column, error)
    CountRows(ctx context.Context, t TableRef) (int64, error)
    // Sample стримит строки; итератор завершается по EOF, ошибке или cancel.
    Sample(ctx context.Context, spec SampleSpec) (iter.Seq2[Row, error], error)
    Close() error
}
```

Правила реализации: `Sample` обязан стратифицировать (случайные сегменты, не head-N);
должен уважать `MaxRows`; ошибка доступа к одной таблице не должна ронять `ListTables`.

### 5.2 Конфигурация сэмплирования

```yaml
scan:
  profile: deep              # quick | deep | custom
  sample:
    mode: percent            # rows | percent
    value: 5
    min_rows: 100            # ниже — берём всё
    max_rows: 20000          # предохранитель
    max_string_chars: 200    # усечение длинных строк
    dedup_values: true       # только уникальные значения в анализ
```

Профили: `quick` = 0.1% / max 2 000 строк; `deep` = 5% / max 20 000; `custom` —
поля выше. Прогрессивное углубление (сначала quick, докрутка неоднозначных до deep)
— опция v2.

### 5.3 Контракт агента (LLM)

Запрос к LLM (OpenAI-compatible, `response_format: json_schema`) — **только**
через Agent Proxy. Тело, которое формирует прокси и который видит агент:

```json
{
  "column_native_type": "String",
  "values": ["4*** **** **** 1234", "+7 *** *** 12 34"],
  "taxonomy_version": "1.0.0"
}
```

Имён БД, таблиц, хостов, путей файлов — быть не должно (на это есть авто-тест
изоляции, п. 16). Ответ — строго один JSON по схеме:

```json
{
  "label": "PHONE",
  "confidence": 0.0,
  "sensitivity": "PII",
  "reason_ru": "1–2 предложения на русском"
}
```

Схема ответа (для `response_format`): `label` — enum из `taxonomy.yaml`;
`confidence` — number 0..1; `sensitivity` — enum `PII|PCI|PHI|none`;
`reason_ru` — string, 1..300 символов. Невалидный ответ — ретрай по п. 6.

**Структура вызова.** System-промпт содержит инструкции, enum лейблов
текущей таксономии, семантику confidence (п. 5.6) и анти-инъекционные
правила (запрет следовать инструкциям из значений); user — JSON-конверт
п. 5.3 со значениями в явных разделителях (`<values>…</values>`). Эта
структура — часть версионируемого промпта: любое изменение = новая
`prompt_version`.

**Пользовательская инструкция на скан (S9-3).** Запуск прогона (UI/API/CLI)
может включать дополнительную инструкцию оператора — контекст предметной
области (≤2000 символов, NUL запрещён, нормализация на границе). Инструкция —
доверенный ввод: передаётся только аутентифицированным субъектам с действием
`scan` (RBAC п. 11.3), добавляется в system-промпт классификатора и
верификатора ПОСЛЕ защищённых правил в блоке `<operator_instruction>` и не
может изменить enum лейблов, схему ответа и анти-инъекционные правила (это
зафиксировано в тексте блока). Ключ кэша вердиктов включает хэш инструкции:
разные инструкции не делят кэш (п. 10.5). Версия базового промпта
(`prompt_base_version`), хэш (`prompt_hash`) и исходный текст сохраняются в
`scans`; аудит старта фиксирует actor/hash/длину без полного текста (п. 14.2).
Scheduled-прогоны всегда идут со стандартным (пустым) промптом. Resume
воспроизводит промпт исходного прогона и сверяет оба значения provenance
fail-closed (п. 13). Per-scan флаг `llm` включает/выключает LLM-слой независимо
от глобального `serve -llm`; отсутствие флага = поведение сервера.

**Режим верификатора** (`escalate_to`, п. 7): прокси отправляет кандидатные
лейблы ансамбля + те же маскированные значения; ответ — строго по схеме:

```json
{"verdict": "confirm | reject", "label": "<из таксономии>",
 "confidence": 0.0, "reason_ru": "1–2 предложения на русском"}
```

`label` при `verdict=confirm` должен совпадать с подтверждаемым; при
`reject` — альтернативный лейбл агента.

Реестр агентов (`detectors.yaml`):

```yaml
agents:
  - id: zond-main
    endpoint: https://api.moonshot.ai/v1/chat/completions # Kimi (Moonshot AI), OpenAI-совместимый (S8-5)
    model: kimi-k2.6
    api_key_env: KIMI_API_KEY      # имя env-переменной, не сам ключ
    max_values_per_call: 25
    timeout_s: 60
    max_retries: 3
    confidence_band: [0.30, 0.70]  # вызывать только в «серой зоне»
    escalate_to: zond-strong # необязательный второй агент-верификатор
```

### 5.4 Модель вердикта

Таблица `verdicts` (логическая модель; физическая — в п. 11.1):

| Поле | Тип | Описание |
|---|---|---|
| `id` | string | SHA-1 length-prefixed `(scan_id, table, path)` — идемпотентная вставка без неоднозначной склейки |
| `scan_id` | string | ссылка на прогон |
| `table` | string | каноническое `schema.table` (для MongoDB — `database.collection`); `\` и `.` внутри компонентов экранируются |
| `path` | string | колонка / путь поля после флаттенинга |
| `native_type` | string | нативный тип |
| `label` | string | лейбл из таксономии |
| `sensitivity` | enum | `PII\|PCI\|PHI\|none` |
| `confidence` | float 0..1 | итоговая уверенность ансамбля |
| `evidence_layer` | enum | `meta\|rules\|llm\|ensemble` — кто решил |
| `evidence` | json | **только маскированные** примеры, matched pattern id, версии |
| `taxonomy_version` | string | semver таксономии на момент вердикта (ADR-0004) |
| `detectors_version` | string | fingerprint `detectors.yaml` |
| `prompt_version` | string | версия промпта (для `evidence_layer=llm`) |
| `sample_size` | int | сколько значений анализировалось |
| `cluster_id` | string | отпечаток кластера колонок (может быть пустым) |
| `review_status` | enum | `auto_accepted\|pending\|confirmed\|rejected\|relabelled` |
| `final_label` | string | метка после ревью (если отличалась) |
| `reviewed_by/at` | string, ts | аудит ревью |
| `created_at` | ts | |

### 5.5 Таксономия (ADR-0004)

Источник — `configs/taxonomy.yaml`, semver. Стартовый набор лейблов
(синхронизирован с промптом и UI):

```
PERSON_NAME, PHONE, EMAIL, ADDRESS, CARD_NUMBER, BANK_ACCOUNT, PASSPORT_ID,
TAX_ID, SNILS, IP_ADDRESS, DATE_OF_BIRTH, GEO_LOCATION, FREE_TEXT,
NUMERIC_MEASURE, IDENTIFIER, DATE_TIME, BOOLEAN, JSON_DOC, UNKNOWN
```

Чувствительность: `PII | PCI | PHI | none`. Словари синонимов имён колонок
(RU/EN) живут там же. Любое изменение файла → рост minor-версии → инвалидация
кэша вердиктов (отпечаток включает версию, п. 10).

Служебные лейблы `DATE_TIME`, `BOOLEAN`, `JSON_DOC` — не PII: выставляются
слоем 0 по нативному типу колонки (и имя, и тип подтверждают), без LLM и
без ревью. Semver-правила таксономии: minor — добавление лейбла; major —
rename/remove с обязательной таблицей alias-маппинга старых лейблов на
новые (дрейф и история не ломаются); patch — правка словарей синонимов.
Полный набор синхронизируется с промптом, UI и генератором eval-датасета
(п. 16.6).

### 5.6 Семантика confidence

Единое соглашение для всех слоёв: **float 0..1**. Якоря:

- `0.99` — детерминированная валидация (контрольная сумма/Luhn совпала);
- `0.80–0.95` — высокая уверенность (сильное regex-совпадение, единогласие слоёв);
- `0.50–0.80` — серая зона, кандидат на LLM/ревью;
- `<0.50` — низкая; при отсутствии сильного конкурирующего лейбла → очередь ревью.

Пороги `tau_accept = 0.80`, `tau_review = 0.50`, серый коридор для вызова агента
`[0.30, 0.70]` — настраиваются в `detectors.yaml`, версионируются вместе с ним.

Источники confidence (как слой ставит число; значения — дефолты
`detectors.yaml`):

| Источник | Confidence |
|---|---|
| слой 1, checksum совпал (Luhn, ИНН, СНИЛС, IBAN, паспорт) | 0.99, конец пайплайна (п. 7.1) |
| слой 1, regex без checksum | доля матчей в сэмпле ≥0.9 → 0.90; 0.5–0.9 → 0.70; <0.5 → 0.50 |
| слой 0, словарь синонимов имён (RU/EN) | 0.85 |
| слой 0, regex имени колонки | 0.60 |
| слой 0, нативный тип + статистика (null, уникальность, длина) | 0.70 |
| слой 2 (LLM) | как вернул агент; во взвешенное голосование идёт без пересчёта |

## 6. Ошибки, ретраи, таймауты

Единая таблица поведения (тестируется контрактными тестами):

| Ситуация | Поведение |
|---|---|
| Коннектор: таблица недоступна / нет прав | Таблица помечается `failed` с причиной; скан продолжается; статус скана `partial` |
| Коннектор: обрыв стрима сэмпла | Чекпоинт (п. 13); таблица `failed`; продолжаем остальные |
| LLM: таймаут / 5xx / 429 | До `max_retries` попыток, backoff 1с→2с→4с + jitter; дальше вердикт `UNKNOWN`, `review_status=pending`, в `evidence` причина `llm_unavailable` |
| LLM: ответ не-JSON / не проходит схему | 1 повтор с repair-инструкцией («return only the JSON object»); далее как выше |
| LLM: лейбл вне таксономии | Приводится к `UNKNOWN` + `pending`, событие в `observe` (сигнал дрейфа промпта) |
| LLM: сэмпл слишком мал (<`min_values_for_llm`, default 10 непустых уникальных) или доля null >0.95 | Вызов не делается; вердикт `UNKNOWN`, `review_status=pending`, причина `small_sample` в `evidence` |
| Resume: не совпал `config_fingerprint`, `taxonomy_version`, `detectors_version` или версия бинарника | Отказ (CLI код 2, API 409) с перечнем всех расхождений; корректный путь — новый скан, старый остаётся в истории |
| Vault недоступен при старте источника (если используется) | Источник `failed` с причиной `vault_unavailable`; остальные источники сканируются; фоновый retry с backoff (п. 12.1) |
| Экспорт больше `export_max_rows` (default 50 000, п. 11.2) | Отказ с кодом `invalid_request` + предложение async-экспорта (фоновая задача, событие в аудите) |
| Невалидный конфиг / секрет не задан | Fail fast на старте команды, код ошибки 2, список проблем в stderr |
| Cancel (Ctrl+C / shutdown) | Плавная остановка, чекпоинт, скан `interrupted`, CLI `scan -resume` либо REST/UI resume по `{id}` |

Идемпотентность: повторный запуск скана с тем же конфигом перезаписывает вердикты
того же `scan_id`-семейства (новый `scan_id`, старые вердикты остаются в истории).

## 7. Каскад анализа и ансамбль

```
слой 0 meta     : regex имени + словарь синонимов + статистика сэмпла (уникальность,
                  длина, доля null) — без сырых значений; сильное совпадение → вердикт
слой 1 rules    : regex по значениям + checksum-валидаторы; матчер с валидной
                  контрольной суммой → confidence 0.99, конец пайплайна для колонки
слой 2 llm      : только серый коридор; вход маскирован; один вызов на колонку; сэмпл
                  < min_values_for_llm или null >0.95 → вызов не делается (small_sample)
слой 3 ensemble : сборка финального вердикта (ниже)
```

Правила ансамбля (фиксируем алгоритм, чтобы не «настраивать веса» вслепую):

1. Любой матчер слоя 1 с прошедшей контрольной суммой → финальный вердикт
   с `confidence 0.99`, слой `rules`. Конкуренции нет (детерминизм побеждает).
2. Иначе — взвешенное голосование слоёв, давших лейбл: веса по умолчанию
   `meta 1.0`, `rules 1.5`, `llm 1.2` (config `ensemble.weights`). Итоговый
   `confidence = Σ(w·c)/Σw`.
3. Если `confidence ≥ tau_accept` и отрыв от второго лейбла ≥ 0.3 → `auto_accepted`.
4. Иначе, если настроен `escalate_to` → вызов второго агента в **режиме
   верификатора** (кандидатные лейблы + маскированные значения; ответ
   `confirm|reject + label`). Верификатор подтвердил → `confidence +0.1`, cap 0.95.
5. Иначе → `review_status=pending` (очередь ручного ревью в веб-UI).

Псевдокод ансамбля (детерминизм: один вход — один вердикт):

    candidates = все лейблы слоёв с (confidence, weight слоя)
    if есть матч слоя 1 с прошедшей checksum:            # правило 1
        return (тот лейбл, 0.99, rules), auto_accepted
    score[l] = Σ(w·c) по слоям, давшим лейбл l
    best, second = топ-1 и топ-2 score
    if best.score ≥ tau_accept and best.score − second.score ≥ 0.3:
        return (best.label, round(score,4), ensemble), auto_accepted
    if escalate_to настроен and best.score в серой зоне:  # правило 4
        верификатор (п. 5.3):
          confirm → (label_v, min(conf+0.1, 0.95)), auto_accepted
          reject  → (label_v, conf_v); далее пересчёт по порогам
    return (best.label или UNKNOWN, score), pending

Множественные матчеры слоя 1 дают независимые кандидатов (каждый со своим
confidence); tie-break при равных score — лексикографически меньший лейбл;
округление score — до 4 знаков одинаково для всех слоёв.

Кластеризация колонок (п. 7.6) действует **до** слоя 2: классифицируется
представитель кластера, вердикт распространяется на колонки с тем же
`cluster_id` с пометкой `cluster_propagated=true` в `evidence`.

### 7.6 Кластеризация колонок

Отпечаток `fingerprint` (пакет `internal/fingerprint`) — входит в ключ кэша
(п. 10.5) и определяет `cluster_id`.

- Признаки отпечатка: нативный тип; классы значений (digit/alpha/mixed/
  empty); min/avg/max длина; доля null; уникальность; энтропия символов;
  префиксные 2 и суффиксные 2 символа (по маскированным значениям).
- Колонки объединяются в кластер при совпадении нативного типа и ≥80%
  остальных признаков (порог `cluster.similarity` в `detectors.yaml`).
  Транзитивное замыкание ограничено: размер кластера ≤`cluster.max_size`
  (default 100), превышение — дробление по энтропии.
- Представитель — первая по порядку колонка скана; остальные получают тот
  же вердикт с `evidence.cluster_propagated=true`.
- Колонки с нестабильным типом (Mongo mixed, п. 8) в кластеризацию не
  включаются.

## 8. Специфика MongoDB

- **Флаттенинг**: вложенные документы → dot-path (`address.city`). Массивы скаляров →
  одна логическая колонка с путём `tags[]` (до K=5 элементов на документ,
  значения склеиваются в общий пул сэмпла). Массивы документов → рекурсия с
  путём `items[].field`, глубина рекурсии ≤ 5, дальше — колонка `...` с лейблом
  `FREE_TEXT` и `pending`-ревью.
- **Полиморфные коллекции**: схема = объединение ключей по сэмплу; отсутствующее
  поле → null в пуле. Путь с нестабильным типом (≥2 типов в >20% документов) →
  `native_type: "mixed"` → принудительно в LLM/ревью, в `evidence` список типов.
- **Типизация путей**: тип значения определяется по BSON-классу значения
  (string/int/decimal/date/bool/objectId/uuid/null); objectId/uuid → сразу
  кандидат `IDENTIFIER` со словарём имён.
- `_id` по умолчанию не классифицируется (`skip: ["_id"]` в конфиге сканирования).
- Сэмпл: `$sample: {size: N}`; при `mode: percent` — `estimatedDocumentCount() * p`,
  cap по `max_rows`. Для шардированных коллекций `$sample` даёт случайный сэмпл
  на текущем кластере — достаточно для MVP, фиксируем в доке ограничение.
- **Нагрузка на источник**: `readPreference: secondaryPreferred` (default,
  настраивается) — `$sample` и прочие чтения не бьют по primary; таймауты
  и лимиты — п. 13.2.

## 9. Специфика ClickHouse

- Схема — из `system.columns`; `system.*`-базы и materialized views исключаем
  (`skip` по умолчанию: `^system\.`, `\.inner\..*`, `^\.` materialized-цели).
- `SampleRows`: таблица с сэмплинг-ключом → `... SAMPLE n WHERE ... LIMIT N`;
  без ключа → `ORDER BY rand() LIMIT N` (дорого: лимитируем `max_rows`,
  в UI помечаем профиль как «медленный»).
- `SamplePercent`: `SELECT ... FROM t SAMPLE p` при наличии ключа, иначе
  `LIMIT toUInt64(count() * p/100)` с предрасчётом `count()`.
- Distributed-таблицы: сканируем как обычную таблицу; углубление в локальные
  шарды — v2.
- Подключение — read-only пользователь, `readonly=2` на уровне настроек
  профиля CH (см. п. 12); в том же профиле — `max_execution_time`
  (default 300 с) и `max_memory_usage` (default 10 ГБ) как защита от
  тяжёлых сэмплов (п. 13.2).
- **Сложные типы** (сопоставимость с флаттенингом Mongo, п. 8):
  `Nullable(T)` — прозрачно (null в пуле, тип T для классификации);
  `LowCardinality(T)`/`FixedString(N)` — как `T`/`String`; `Array(T)` →
  одна логическая колонка с путём `col[]` (K=5 элементов на строку, общий
  пул сэмпла); `Tuple`/`Nested` → dot-path `col.field`, глубина ≤5 (дальше
  `...` + `FREE_TEXT` + pending); `Map(k,v)` → логические колонки
  `col.{key}` по ключам из сэмпла (до 20 ключей, дальше `col.*` + pending).

## 10. Agent Proxy

Единственная точка вызова LLM. Ответственность:

1. **Изоляция**: формирует тело запроса строго по п. 5.3; ни один другой пакет
   не имеет права импортировать HTTP-клиент LLM (проверяется линтом
   `depguard` в golangci-lint).
2. **Маскирование**: перед отправкой прогоняет значения через `mask/` по
   маск-профилю (`detectors.yaml`; версия входит в ключ кэша, п. 10.5).
   Базовый профиль:

   | Тип | Правило | Пример |
   |---|---|---|
   | PAN/карта | первые 6 и последние 4 видны; длина и разделители сохраняются | `4*** **** **** 1234` |
   | Телефон | код страны/города и последние 2 цифры | `+7 *** *** 12 34` |
   | ИНН/СНИЛС/паспорт/счёт | первый и последний символы; длина сохраняется | `7*************3` |
   | Email | локальная часть: первый символ + `***`; домен открыт | `a***@example.com` |
   | IP-адрес | последний октет скрыт | `10.0.0.*` |
   | Прочее (FREE_TEXT) | фрагменты, найденные слоем 1, → плейсхолдеры (`<CARD>`, `<PHONE>`, `<EMAIL>`); строки длиннее `max_string_chars` усечены (п. 5.2) | — |

   Значения длиной ≤4 символов не маскируются и **исключаются из пула,
   отправляемого агенту**: классификации они не дают, а re-identification
   риск максимален.
3. **Сессии**: один вызов = один system+user; никакого многоходового диалога.
4. **Лимиты**: семафор конкурентных вызовов (default 8), глобальный rate-limit
   запросов/сек, budget-стоп: при `cost_scan_limit_usd` скан останавливается
   с статусом `budget_exceeded` (неотвеченные колонки → `pending`).
5. **Кэш вердиктов**: ключ = `sha256( agent_id | model | prompt_version |
   taxonomy_version | mask_profile_version | user_prompt_hash |
   fingerprint(values) )`,
   где `fingerprint(values)` — отпечаток отсортированных уникальных усечённых
   значений. Хранение в таблице `verdict_cache` с TTL (default 30 дней).
   Смена любой версии → другой ключ → естественная инвалидация.
   `user_prompt_hash` (S9-3) — хэш пользовательской инструкции скана; пустой
   для стандартного промпта.
6. **Учёт**: каждый вызов → строка в `agent_calls` (п. 11.1) в одной транзакции
   с записью вердикта.
7. **Контур**: поддержка локальных OpenAI-совместимых эндпоинтов
   (Ollama, llama.cpp-server, vLLM) — опция «полностью локальный контур»
   без единого внешнего вызова. **Allowlist по умолчанию пуст**: разрешены
   только loopback и приватные диапазоны (RFC 1918); публичный эндпоинт —
   только явной записью в `agents.*.allowlist`. Флаг `offline: true`
   запрещает любые эндпоинты вне allowlist. Это закрывает SSRF из прокси.

## 11. Verdict Store, REST API и веб-UI

### 11.1 Схема SQLite (миграции goose)

```sql
sources(id, type, name, conn_ref, created_at)
scans(id, source_name, profile, config_fingerprint, taxonomy_version,
      detectors_version, binary_version, table_identity_version,
      prompt_base_version, prompt_hash, prompt_text, llm_enabled,
      started_at, finished_at, status, stats_json) -- status: running|partial|done|interrupted|failed|budget_exceeded
scan_tables(scan_id, table_name, row_count, status, error)
columns(scan_id, table_name, path, native_type, stats_json, cluster_id)
verdicts(...)                                   -- п. 5.4
verdict_cache(cache_key, agent_id, verdict_json, created_at, expires_at)
agent_calls(id, scan_id, verdict_id, agent_id, model, prompt_version,
            tokens_in, tokens_out, cost_usd, latency_ms, cached, status, created_at)
model_prices(model, per_1m_in, per_1m_out, effective_from)  -- прайс-лист для cost_usd
review_events(id, verdict_id, action, from_label, to_label, actor, ts)  -- append-only аудит ревью
users(subject PK, display_name, role, last_login_at)  -- JIT-прvisioning из SAML (ADR-0011)
audit_log(seq PK, ts, actor, category, action, target, details_json,
          prev_hash, entry_hash)                       -- append-only, п. 14.2
api_tokens(id, name, scopes, key_hash, issued_by, created_at,
           expires_at, revoked_at, last_used_at)       -- п. 14.2
```

`stats_json` скана: `columns_total, by_layer{meta,rules,llm,cache}, tokens_in/out,
cost_usd, duration_s, llm_share` — источник метрик п. 17.

Физические правила: `PRAGMA journal_mode=WAL`, `busy_timeout=5000`,
`foreign_keys=ON`; единственный писатель — внутренняя очередь записи
(п. 15.1). Индексы: `verdicts(scan_id)`, `verdicts(review_status)`,
`verdicts(label)`, `verdicts(cluster_id)`, `agent_calls(scan_id)`,
`audit_log(ts)`, `audit_log(actor)`. Прочистка просроченного
`verdict_cache` — фоновая задача шедулера (п. 15.4).

### 11.2 REST API (v1, JSON; то же API использует UI)

| Метод | Путь | Назначение |
|---|---|---|
| POST | `/api/v1/scans` | старт скана `{source, profile}` → `{scan_id}` |
| GET | `/api/v1/scans` | список прогонов (пагинация, фильтр по статусу/источнику) |
| GET | `/api/v1/scans/{id}` | статус, прогресс, stats_json |
| POST | `/api/v1/scans/{id}/stop` | мягкая остановка |
| POST | `/api/v1/scans/{id}/resume` | новый прогон по done-чекпоинтам partial/interrupted после сверки provenance → 202 `{scan_id, resume_from}`; несовместимость → 409 `resume_incompatible` со списком `mismatches` |
| GET | `/api/v1/verdicts` | фильтры: `scan_id, label, sensitivity, min_conf, review_status, table, cluster_id`; сортировка `risk_first` (PCI/PII × confidence desc) |
| GET | `/api/v1/verdicts/{id}` | детали; evidence уже маскирован (ADR-0010) |
| POST | `/api/v1/verdicts/{id}/review` | `{action: confirm|reject|relabel, label?}` → запись в `review_events`, смена `review_status` |
| GET | `/api/v1/drift?source_id=&since=` | новые/исчезнувшие колонки, смены вердиктов между сканами |
| GET | `/api/v1/stats/cost?scan_id=` | токены/стоимость по агентам и моделям |
| GET | `/api/v1/export?scan_id=&format=csv|json` | выгрузка вердиктов |
| GET | `/api/health`, `/api/ready` | liveness/readiness |

Все мутации (POST), экспорт и аудит — только аутентифицированно: SSO-сессия
(п. 11.3) или API-токен со scope (п. 14.2); каждый запрос получает correlation
id (`X-Request-ID`) и событие в аудит-логе.

Ошибки API — единый конверт `{error: {code, message, details}}`, коды:
`invalid_request, source_unavailable, scan_not_found, review_conflict, resume_incompatible, internal`.

Лимиты: экспорт сверх `export_max_rows` (default 50 000) — отказ с
предложением async-экспорта (фоновая задача, результат по ссылке, событие
в аудите); общий rate-limit — 100 req/s на SSO-сессию или API-токен
(настраивается).

### 11.3 Веб-UI (ADR-0007)

Страницы (server-rendered, HTMX для динамики, всё из embed.FS):

- `/scans` — прогоны: статус-бейджи, прогресс-бары, кнопки start/stop/resume,
  бейдж `budget_exceeded`.
- `/scans/{id}` — дашборд прогона: разложение «кем решено» (слои 0/1/кэш/LLM),
  токены и `$`, таблицы с проблемами.
- `/verdicts` — основная таблица анализа: фильтры по лейблу/чувствительности/
  статусу ревью, поиск по таблице/пути, сортировка «риск первыми», маскированные
  примеры значений, бейжи evidence_layer, переход к ревью.
- `/review` — очередь ручного ревью: карточка вердикта (маскированные примеры,
  reason_ru, вклад слоёв), действия «подтвердить / отклонить / пере-классифицировать»,
  клавиатурные shortcuts (y/n/l), bulk-подтверждение/отклонение выбранных карточек. Подтверждения/отклонения пишутся в `review_events`
  (петля обратной связи; авто-подстройка порогов — v2).
- `/drift` — дифф двух сканов: новые колонки, исчезнувшие, смены лейблов/уверенности.
- `/cost` — экономика: токены/стоимость по агентам, моделям, сканам; доля решённого
  без LLM (цель ≥70%).
- `/settings` — источники, реестр агентов (редактирование YAML с валидацией),
  пороги ансамбля, таксономия (read-only просмотр версии).

RBAC-матрица (операция × роль):

| Действие | admin | viewer |
|---|---|---|
| Просмотр сканов/вердиктов/дрейфа/стоимости | + | + |
| Экспорт CSV/JSON (API и UI) | + | − |
| Ручное ревью (confirm/reject/relabel) | + | − |
| Старт/стоп/резюм сканов, расписание | + | − |
| Настройки (источники, агенты, пороги) | + | − |
| Просмотр аудита (`/audit`) | + | − |

Аутентификация — **SSO SAML 2.0** (ADR-0011): встроенный Service Provider,
вход через корпоративный IdP (Keycloak, ADFS, Entra ID и др.); поддержка
Signed/Encrypted assertions, HTTP-POST binding, Single Logout. Пользователи
провижионируются JIT в `users` при первом входе. Роли: `admin` (ревью, настройки,
управление сканами) и `viewer` (просмотр вердиктов/отчётов, без действий);
маппинг ролей — из SAML-атрибута (напр. `Role`) или членства в группах,
настраивается в `sso:`-блоке конфигурации. Аудит ревью (`review_events`) пишет
SSO-личность ревьюера. Локальный админ-токен из env `CLASSIFIER_ADMIN_TOKEN`
сохраняется только как bootstrap (первая настройка) и аварийный доступ при
недоступности IdP; в штатном режиме отключается флагом `admin_token_fallback: false`.

Эксплуатация SSO: метаданные IdP подтягиваются по `idp_metadata_url` при
старте и далее каждые 24 ч (`sso.metadata_refresh`), с валидацией подписи;
ротация ключей IdP принимается без перезапуска. Сертификат подписи SP —
файл в конфигурации; замена по процедуре «добавить новый → раскатать →
убрать старый» с перекрытием, без даунтайма. Пользователь в группах admin
и viewer одновременно получает `admin` (максимальная роль). SSO-сессии —
в памяти процесса: рестарт разлогинивает всех (приемлемо для
single-instance, п. 15.1).

## 12. Конфигурация и секреты

Три файла (ADR-0009), валидация схемы на старте, fail-fast:

```yaml
# connections.yaml — профили БД, БЕЗ секретов
sources:
  - name: ch-prod
    type: clickhouse
    dsn: "clickhouse://readonly:${CH_PROD_PASSWORD}@ch-host:9000/analytics"
    # либо: host/port/database + credentials_env: [CH_PROD_PASSWORD]
  - name: mongo-prod
    type: mongodb
    uri: "${MONGO_PROD_URI}"

sso:                            # веб-UI: вход через корпоративный IdP (ADR-0011)
  enabled: true
  entity_id: "https://zond.example.com/saml/metadata"
  acs_url: "https://zond.example.com/saml/acs"
  idp_metadata_url: "${IDP_METADATA_URL}"   # либо idp_metadata_file: ./idp.xml
  name_id_format: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
  role_attribute: "Role"                    # admin | viewer; fallback — группы IdP
  admin_token_fallback: true                # CLASSIFIER_ADMIN_TOKEN при недоступности IdP
```

- Блок `sso:` содержит только публичные параметры SP и ссылку на метаданные IdP;
  секретов в нём нет. `enabled: false` — режим без SSO (только admin-токен,
  для dev-контура и air-gapped без IdP).

- Интерполяция `${VAR}` из окружения; если переменная не задана — fail-fast с
  перечнем недостающих.
- Рекомендуемые учётки: CH — пользователь `readonly` с `readonly=2`;
  Mongo — роль `read` на целевые БД; ограничение network-ACL снаружи.
- `detectors.yaml` — слои 0–1 (словари, recognizer'ы, пороги), реестр агентов
  (п. 5.3), веса ансамбля, `cost_scan_limit_usd`, маск-профиль.
- Пример переменных: `KIMI_API_KEY`, `CH_PROD_PASSWORD`, `MONGO_PROD_URI`,
  `CLASSIFIER_ADMIN_TOKEN`.

`detectors.yaml` перечитывается без рестарта (ADR-0014): каждая правка
валидируется по схеме; при успехе бампится `detectors_version` и пишется
событие аудита с diff «было → стало» (п. 14.2); при ошибке действует
прежняя версия. Применяется к новым вызовам немедленно; кэш вердиктов
инвалидируется естественно — через смену версий в ключе (п. 10.5).
`connections.yaml` и блок `sso:` — только рестарт.

### 12.1 Опция: HashiCorp Vault — секреты без хранения на сервере (ADR-0012)

```yaml
# connections.yaml, блок vault — секреты БД из Vault вместо ENV
vault:
  enabled: true
  address: "https://vault.example.com"
  auth:
    method: kubernetes        # контур K8s: JWT сервис-аккаунта
    role: zond
    # method: token + token_env: VAULT_TOKEN   # только dev/демо!
  secrets:
    - ref: ch-prod            # совпадает с name источника
      path: database/creds/ch-prod-readonly   # dynamic: лиза с авто-ротацией
    - ref: mongo-prod
      path: kv/data/zond/mongo-prod     # kv-v2: ключ uri=...
      key: uri
```

Правила:

- Секрет читается `internal/secrets` **в момент установки коннекта** и живёт
  только в памяти процесса; на диск, в конфиг и в логи не попадает (redact,
  п. 14.1). DSN/URI в `sources` при включённом Vault не указываются — только
  `ref` на запись `vault.secrets`.
- Dynamic-лиз продлевается фоновой горутиной; при истечении — прозрачный
  реконнект с новым секретом. Ротация — на стороне Vault, без перезапуска
  сервиса и без правки конфигов.
- Аутентификация в Vault: kubernetes-роль (prod) или token из ENV (dev);
  token в конфиге запрещён. События резолва и ротации — в аудит-лог (без
  значений, п. 14.2).
- Без Vault (`enabled: false` или блок отсутствует) — прежний режим `${ENV}`
  (dev, air-gapped, инсталляции без Vault).
- Альтернатива «Vault Agent sidecar + файлы в shared volume» допустима в
  enterprise-инсталляциях, но не требуется: нативный `Resolver` закрывает
  сценарий полностью.

## 13. Отказоустойчивость и чекпоинты

- Скан — конечный автомат: `running → (done | partial | interrupted | failed |
  budget_exceeded)`; переходы фиксируются в `scans.status` транзакционно.
- Чекпоинт после каждой таблицы: `scan_tables.status` + commit вердиктов таблицы;
  ключ и `verdicts.table_name` — каноническое `schema.table` (S9-1).
  CLI `zond scan -resume` продолжает последний partial/interrupted прогон источника;
  REST/UI продолжают явно выбранный `{id}`. Пропускаются только `done`-таблицы.
  Допускается, только если совпали `config_fingerprint`, `taxonomy_version`,
  `detectors_version` и версия бинарника; иначе отказ (CLI код 2, API 409)
  с перечнем всех расхождений. Пустой provenance старых строк — несовместимость,
  а не разрешение. С S9-3 сверяются также `prompt_base_version` и
  `prompt_hash` (S9-3): продолжение воспроизводит промпт исходного прогона
  (сохранённый в `scans.prompt_text`) и флаг `llm_enabled`; задать другой
  промпт при продолжении нельзя — только новый прогон.
- Вызовы LLM атомарны относительно вердикта: либо `agent_calls`+`verdicts`,
  либо откат (отсутствие «висящих» вердиктов без учётной записи).
- Потребление памяти потоковое: сэмпл стримится (iter.Seq2), пул значений
  колонки ограничен `max_rows × max_string_chars`; никаких «прочитать всю таблицу
  в память».
- Graceful shutdown: отмена контекстов, доведение текущих LLM-вызовов до
  retry-safe точки (или откат), скан → `interrupted`.

### 13.2 Нагрузка на источники (resource governance)

Сканер не должен деградировать продуктивные БД:

- Лимиты на источник (в записи `sources` `connections.yaml`):
  `max_concurrent_scans` (default 1), `max_concurrent_tables` (default 2),
  таймаут запроса к БД (default 5 мин); retry — только на retryable-ошибки
  драйвера (перегрузка, потеря лидерства), иначе таблица → `failed`.
- Circuit breaker per source: 5 подряд `failed`-таблиц по причине
  `source_overload` → пауза источника на 5 мин; скан → `partial`, доступен
  `--resume`.
- Окна сканирования (опция): `scan_window: "02:00-06:00"` — старт вне
  окна откладывается шедулером.
- СУБД-специфика: Mongo `secondaryPreferred` (п. 8), профиль CH readonly
  с `max_execution_time`/`max_memory_usage` (п. 9).

## 14. Безопасность системы

Система сама обращается с PII → применяем к себе те же требования:

| Угроза | Мера |
|---|---|
| Утечка через LLM | Agent Proxy — единственный egress; маскирование (ADR-0010); `offline: true` / allowlist эндпоинтов; опция локального контура (Ollama/vLLM) |
| Утечка из Verdict Store | В БД — только маскированные evidence; шифрование диска/раздела с файлом БД (LUKS/BitLocker) — требование к инсталляции, проверяемое в `preflight`; бэкапы под тем же шифрованием |
| Несанкционированный доступ к UI/API | SSO SAML 2.0 с валидируемыми подписанными assertions, роли admin/viewer, локальный токен только как аварийный fallback, TLS за reverse-proxy, аудит ревью привязан к SSO-личности (`review_events`, append-only) |
| Компрометация секретов БД | Только env/docker secrets или Vault с динамическими лизами и авто-ротацией без хранения на сервере (ADR-0012, п. 12.1); интерполяция на лету; секреты не попадают в логи/вердикты/трейсы (redact, п. 14.1) |
| Эскалация прав из сканера | Документированные least-privilege-роли (п. 12); сетевые ACL; таймауты запросов на стороне БД |
| Подмена данных от «агента» | Валидация ответа по JSON-схеме; allowlist эндпоинтов; mTLS/токен — на усмотрение инсталляции |
| Подмена или удаление журнала аудита | append-only `audit_log` + hash-chain и триггер миграции против UPDATE/DELETE; внешний sink в SIEM; подписанные снапшоты (WORM) — п. 14.2 |
| Brute-force admin-токена (fallback) | Rate-limit и временная блокировка на эндпоинте входа (настраивается); каждое использование — warn-событие в аудите; рекомендация держать fallback выключенным |
| CSRF / угон сессии | CSRF-токены во всех HTMX-мутациях; cookie `HttpOnly; Secure; SameSite=Lax`; idle-timeout сессии (default 12 ч); ротация session id после логина |
| XSS через LLM-ответы (`reason_ru`) и пользовательские данные в UI | `html/template` с контекстным экранированием (запрещён `safeHTML` для пользовательского контента), CSP `default-src 'self'`, заголовки `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer` |
| SSRF из Agent Proxy наружу | Allowlist по умолчанию пуст — только loopback/RFC 1918 (п. 10.7); публичные адреса — только явной записью |
| Перегрузка продуктивной БД сканированием | Resource governance (п. 13.2): лимиты на источник, circuit breaker, окна сканирования; least-privilege-учётки (п. 12) |
| Prompt injection через значения из БД | Значения передаются как данные: обрамление/экранирование, запрет следовать инструкциям из значений в system-промпте, ответ строго по JSON-схеме; LLM физически не может инициировать действия — только классифицировать; подозрительные значения → `UNKNOWN` + ревью |
| Вредоносная/слишком длинная пользовательская инструкция (S9-3) | Инструкция — доверенный ввод: только RBAC `scan`, лимит 2000 символов и запрет NUL на границе (UI/API/CLI/runner), append-only блок после защищённых правил с фиксацией их неотменяемости, хэш в ключе кэша и provenance скана, аудит actor/hash/длины; конверт по-прежнему без идентификаторов инфраструктуры |
| Replay SAML-assertions | Проверка `InResponseTo`/хронology, краткоживущие временные метки (clock skew ≤ 60 с), replay-кэш идентификаторов ответов |
| Уязвимости зависимостей и образа | `govulncheck` в CI (блокирует High/Critical), SBOM (syft) на каждый релиз, scratch-образ, non-root (UID 65534), read-only root FS |
| Неконтролируемый экспорт вердиктов | Scope `export` у API-токенов; событие экспорта в аудите (кто/скан/формат/число строк); в выгрузке только маскированные evidence (ADR-0010) |
| Исчерпание бюджета через LLM | Лимит стоимости на скан (стоп со статусом `budget_exceeded`), семафор и rate-limit вызовов, квота на источник — п. 10 |

### 14.1 Операционное логирование (ADR-0013)

- **Формат**: structured JSON, один объект на событие: `ts, level, msg,
  correlation_id, actor, component, outcome, error, duration_ms`. Вывод —
  stdout (контейнер) или файл с ротацией `lumberjack` (по размеру, retention
  ≥14 дней, настраивается).
- **Уровни**: `debug | info | warn | error`. В проде уровень `debug` запрещён
  для пакетов `agentproxy`, `connector`, `sampler` — они ближе всего к данным.
- **Correlation id**: пробрасывается из HTTP-заголовка `X-Request-ID` через
  все слои до вызова агента (связь с `agent_calls`) и в обратную сторону в
  ответ (`X-Request-ID`), чтобы UI/API/агентные действия были сшиты в одну
  цепочку.
- **Redact middleware (обязательная)**: единая точка в `internal/logging`,
  которая перед записью маскирует секреты (DSN, URI, токены, заголовок
  Authorization, значения из Vault), PII-подобные строки и тела запросов к
  LLM. Авто-тест в CI: прогон сэмпла данных с «метками-ловушками» через
  логирование → ни одна ловушка не встречается в захваченных логах.

### 14.2 Аудит действий (security audit log, append-only)

Принцип: **все действия логируются** — веб-UI, REST API, CLI, агентные вызовы,
фоновые задачи (шедулер, продление лиз Vault).

- **Хранение**: таблица `audit_log` — только INSERT (на уровне кода и
  триггером миграции запрещены UPDATE/DELETE), **цепочка хэшей**
  `entry_hash = sha256(prev_hash | canonical(entry))` для обнаружения
  подмены/удаления; опционально — периодическая подписанная выгрузка-снапшот
  наружу (WORM/S3 Object Lock).
- Формат `canonical(entry)`: сериализация фиксированного набора полей
  (`seq,ts,actor,category,action,target,details_json`) в UTF-8 JSON с
  отсортированными ключами, терминатор `\n`. Запись в `audit_log` строго
  последовательна (mutex писателя); hash-chain считается в той же транзакции,
  что INSERT.
- **Внешний sink (опция)**: syslog/CEF или JSON-over-TCP в SIEM
  (`audit.sink` в конфиге); при недоступности sink — локальная очередь с
  повторной отправкой, потеря событий недопустима.
- **Минимальный набор событий**:
  - *Аутентификация*: SSO login success/failure (с причиной), logout, SLO;
    каждое использование admin-токена — всегда уровень `warn`;
  - *Авторизация*: отказы 403 (роль, ресурс, subject);
  - *Ревью*: confirm/reject/relabel (verdict id, from→to label, actor);
  - *Сканы*: start/stop/resume/finish со статусом и сводкой
    (колонки, по слоям, токены, `$`);
  - *Агенты*: каждый вызов (agent_id, model, prompt_version, cached,
    tokens, cost, latency, outcome) со ссылкой на `agent_calls`;
  - *Конфигурация*: изменения sources / агентов / порогов / маск-профиля /
    смена версии таксономии — с diff «было → стало» и actor;
  - *Экспорт*: кто, какой скан, формат, число строк;
  - *Секреты*: факт резолва из Vault/ENV и ротация лизы — без значений;
  - *Администрирование*: смена ролей, выпуск/отзыв API-токенов.
- **Программный доступ к API** (для CI/интеграций, в обход SSO): отдельные
  API-токены с scope `read | review | export | admin`, выпуск через
  `zond token issue`, хранение только хэшем (argon2), отзыв —
  мгновенный; действия токена в аудите с `actor = token:<id>`.
- API-токены имеют срок действия (default 90 дней, настраивается);
  `last_used_at` обновляется не чаще раза в час. Ротация — выпуск нового
  и отзыв старого (`zond token issue|revoke`); отзыв мгновенный.
- **Доступ**: просмотр аудита — только роль `admin`, страница `/audit` в UI
  (фильтры по actor/типу/дате/scan_id) и `zond audit export`.
  Ретенция ≥180 дней либо выгрузка в SIEM; архивы проверяются по hash-chain.

## 15. Деплой и эксплуатация

- **Артефакт**: один бинарник `zond` + файлы конфигурации. Команды:
  `scan`, `serve` (API+UI), `migrate`, `eval`, `seed`, `agent-check`
  (проверка доступности/формата ответа агента на тестовых значениях).
- **Dev/demo-контур**: `deploy/docker-compose.yml` = app + ClickHouse + MongoDB +
  seed-контейнер (`make smoke` — подъём и один скан quick-профилем, зелёный
  smoke = скан дошёл до статуса done и в UI видны вердикты).
- **Прод**: бинарник как systemd-unit / контейнер `scratch`-образа; SQLite на
  смонтированном томе; за ним reverse-proxy с TLS.
- **Харденинг контейнера**: scratch-без-шелла, non-root (UID 65534), read-only
  root FS + tmpfs для `/tmp`, секреты только через env/Vault — никогда в слоях
  образа; релиз подписывается (cosign) и сопровождается checksums и SBOM
  (syft) — все три артефакта в релизном чеклисте.
- **Расписание**: встроенный cron (`schedule: "0 2 * * *"` в конфиге источника)
  для периодических пересканов; дрейф — сравнение с предыдущим сканом.
- **Air-gapped**: сборка без сетевых вызовов на старте, embed-статика UI,
  HTMX vendored, LLM — локальный эндпоинт, никаких телеметрий наружу
  (OTL экспортер по умолчанию off).

### 15.1 Процессная модель

Один инстанс = один процесс `serve`: API, веб-UI, шедулер и встроенные
сканы работают внутри него; подкоманда `scan` — тот же код для CI и
one-shot-запусков. SQLite — единственная БД инстанса (WAL, п. 11.1):
чтение UI не блокирует запись скана. Несколько реплик / HA — вне скоупа
(п. 20): масштабирование вертикальное + лимиты п. 13.2; multi-node —
позже, через слой PostgreSQL-хранилища (ADR-0006).

### 15.2 Резервное копирование Verdict Store

- `zond backup --out <path>`: онлайн-копия через `VACUUM INTO`
  (без остановки сервиса), шифрование — на уровне ФС/диска (п. 14);
  расписание — cron инстанса или `schedule` в конфиге.
- RPO ≤24 ч; раз в релиз — учебное восстановление в пустой инстанс
  (`migrate` + проверка hash-chain аудита) — обязательно в DoD (п. 22).
- Копии хранятся вне инстанса (S3/WORM — по той же политике, что
  снапшоты аудита, п. 14.2).

### 15.3 Preflight (`zond doctor`)

Проверки перед вводом в эксплуатацию: свободное место на томе SQLite
(≥2× размера БД); доступность каждого источника (`Ping` + probe `SELECT`
под readonly-учёткой); доступность и формат ответа каждого агента
(`agent-check`); Vault (если enabled); TLS-сертификаты; DNS; наличие
обязательных env. Выход — таблица OK/FAIL с кодами; FAIL блокирует старт
`serve` при флаге `--strict`.

### 15.4 Retention

| Данные | Срок | Механизм |
|---|---|---|
| `audit_log` | ≥180 дней (п. 14.2) | архив + проверка hash-chain |
| сканы + вердикты | ≥90 дней | автоочистка шедулером; факт очистки — в аудит |
| `agent_calls` | ≥90 дней | вместе со сканом |
| `verdict_cache` | TTL 30 дней | фоновая прочистка ежедневно |

## 16. Тестирование и eval

Пирамида и обязательные наборы:

1. **Unit**: матчеры слоя 1 против золотых векторов (`vectors_test.go`):
   ≥50 валидных + ≥50 невалидных значений на тип (ИНН 10/12, СНИЛС, паспорт,
   счета 40802/40702, Luhn, IBAN, E.164/RU-телефоны, IPv4/6, даты);
   маскировщики — табличные тесты; fingerprint — стабильность.
2. **Контрактные тесты коннекторов**: общий пакет `conftest.RunConformance`
   (одна и та же фикстура данных, прогоняется против CH и Mongo через
   testcontainers-go): ListTables/GetSchema/CountRows/Sample на идентичных
   данных дают сопоставимые результаты; соблюдение MaxRows; стратификация
   (стат-тест: распределение не хуже равномерного по партициям).
3. **Изоляционные тесты Agent Proxy**: fake-LLM (httptest) записывает тело
   запроса; авто-тест проверяет, что в теле нет строк: имён БД/таблиц/хостов,
   сырых PAN/телефонов (маскирование), и что каждый вызов — независимый
   (нет сквозного контекста).
4. **Ensemble**: синтетические наборы «слои расходятся» → проверка правил
   п. 7 (checksum побеждает; эскалация вызывается; иначе pending).
5. **Интеграционные**: полный скан тестового контура (compose) на зелень;
   SSO-флоу (SP-initiated login, роли, SLO) против Keycloak в testcontainers.
6. **Eval-harness** (`cmd/eval`, стартует на 3-й неделе, не ждём этапа 6):
   генератор эталонного датасета (Go, Faker-аналог): 1000 колонок × все лейблы таксономии (п. 5.5),
   включая негатив (PII внутри свободного текста, похожие но неверные
   контрольные суммы, mixed-типы Mongo, полиморфные коллекции). Метрики:
   precision/recall/F1 по каждому лейблу; sweep порогов `tau_*`; отчёт
   «токены и $ на 1000 колонок». Датасет и отчёты — в репозитории (`evals/`).
7. **CI-ворота**: `go vet`, `golangci-lint`, `go test -race ./...`,
   покрытие ≥70% на `internal/analyze/rules`, `internal/agentproxy`,
   `internal/ensemble`; `go-licenses` (бан GPL/Commons Clause в зависимостях);
   `govulncheck` без находок High/Critical; SBOM (syft) генерируется на релиз;
   контрактные и изоляционные тесты — обязательны на каждый PR.
8. **Нагрузочный тест**: `make bench` — слой 1 на 1M синтетических значений;
   проверка NFR п. 18 (≥100 000 значений/мин на ядро); прогон в CI на
   каждый PR, метрика — в отчёте.
9. **Миграции**: тест `goose up → down → up` на чистой БД + открытие БД
   после каждого шага (п. 11.1).
10. **Fuzz**: `go test -fuzz` для парсеров — BSON-флаттенинг (п. 8),
    YAML-конфига, JSON-ответа агента (п. 5.3), маскировщиков (п. 10.2);
    corpus-сиды закоммичены, прогон в CI.

## 17. Метрики и инструментация

- **Бизнес-метрики** (цели из п. 22, источник — `scans.stats_json` и `agent_calls`):
  доля колонок, решённых без LLM (цель ≥70%); токены/1000 колонок и `$` на скан;
  доля `pending` после ревью, переведённых в `confirmed` (качество ансамбля).
- **Технические**: latency слоёв и вызовов (p50/p95 из `agent_calls.latency_ms`),
  доля кэш-попаданий, число retry, `llm_unavailable`-события.
- **Экспозиция**: expvar (`/debug/vars`), опционально OTLP-трейсы;
  дашборды — страницы `/scans/{id}` и `/cost` встроенного UI.
- **Алертинг (встроенный)**: события в UI и опциональный webhook:
  `budget_exceeded`, рост `pending` сверх порога (R9), серия
  `llm_unavailable` (>5 подряд), разрыв hash-chain аудита (п. 14.2),
  неуспешный бэкап (п. 15.2). Интеграции Slack/Telegram — вне скоупа
  (п. 20); внешняя доставка — через SIEM-sink (п. 14.2).
- **Атрибуция стоимости**: `cost_usd` считается из `model_prices` по токенам
  вызова; сверка с реальным счётом провайдера — ежемесячно руками, дельта <15%.

## 18. Нефункциональные требования

- Пропускная способность слоя 1: ≥100 000 значений/мин на 1 CPU-ядре.
- Потребление памяти скана: ≤512 МБ RSS при `max_rows=20000` на таблицу
  (потоковая обработка, п. 13).
- Конкурентность: пул воркеров на таблицы (default 4) + семафор LLM (default 8);
  конфигурируется, race-detector зелёный в CI.
- Время холодного старта сервера: ≤2 с (включая миграции SQLite).
- Размер бинарника: ≤60 МБ (embed UI + промпты).
- Поддерживаемые платформы сборки: linux/amd64, linux/arm64, windows/amd64.

## 18.1 Версионирование API, конфигов и миграций

Чтобы проект не потерял управляемость после первых релизов, вводим явные правила
совместимости:

- **REST API** версионируется в пути (`/api/v1/...`). Любое несовместимое изменение
  контракта ответа/запроса — только через `v2`; совместимые поля можно добавлять
  в `v1`, если клиенты могут их игнорировать.
- **JSON-ошибки** (`{error:{code,message,details}}`) считаются публичным контрактом.
  Нельзя менять значения `code` без новой версии API.
- **YAML-конфиги** (`connections.yaml`, `detectors.yaml`, `taxonomy.yaml`) получают
  поле `version`. При несовместимом изменении схемы бинарник обязан либо выполнить
  детерминированную миграцию, либо завершиться с fail-fast и сообщением, как
  обновить файл.
- **SQLite-миграции** — только вперёд в production. Каждая миграция обязана быть
  идемпотентной относительно пустой/актуальной БД и сопровождаться тестом
  `up → open → smoke query`; `down` — только для dev/test (п. 16.9).
- **Таксономия** уже semver-версионируется (ADR-0004); аналогичное правило вводится
  для **формата evidence** и `stats_json`: несовместимые изменения требуют bump
  версии структуры и адаптера чтения в UI.
- **Prompt-version**, `detectors_version`, `taxonomy_version`, версия бинарника и
  версия конфигов фиксируются в каждом скане как часть provenance. Это упрощает
  разбор инцидентов и сравнение результатов между релизами.

## 18.2 Data governance и privacy-by-design

Кроме технической безопасности, системе нужна управляемая политика обращения с
данными:

- **Минимизация данных**: в Verdict Store, логах, аудите, экспорте и метриках
  запрещены сырые значения; маскированные evidence дополнительно ограничиваются по
  длине и количеству примеров на колонку.
- **Классы данных продукта**: отдельно определить, какие данные считаются
  `operational`, `security_audit`, `masked_evidence`, `temporary_runtime`. Для
  каждого класса — владелец, срок хранения, место хранения и правила экспорта.
- **Политика экспорта**: CSV/JSON-экспорт должен иметь watermark в аудите
  (`actor`, `reason`, `scan_id`, `row_count`) и явный лимит на массовые выгрузки.
  Для enterprise-контуров рекомендован async-экспорт с одноразовой ссылкой и TTL.
- **Right-to-know для оператора**: UI должен явно показывать, какие данные могли
  уйти во внешний LLM, какой mask-profile применился и был ли запрос кэширован.
- **Privacy-review на новые recognizer'ы и агенты**: каждый новый matcher,
  маскировщик и внешний endpoint проходит короткий чеклист: что получает, где
  хранит, как логируется, чем ограничен egress.

## 19. Реестр рисков

Владелец = роль в команде (п. 21). П/И — вероятность/импакт (H/M/L).
Триггер — событие, по которому риск пересматривается.

| # | Риск | П/И | Митигация | Владелец | Триггер |
|---|---|---|---|---|---|
| R1 | Кросс-доменная точность семантических типов ниже цели (бенчмарки OSS ≈0.54 F1) | H/H | Ансамбль + очередь ревью с первого релиза; настройка порогов на данных заказчика; честные метрики в `/cost` | Tech Lead | Eval после этапа 4: F1 семантики <0.75 |
| R2 | В MVP нет локального NER (ADR-0003) → в LLM уходит больше колонок, экономика хуже | M/M | Кластеризация колонок, кэш, жёсткие пороги серой зоны; лимит бюджета на скан; v2 — ONNX sidecar | Tech Lead | Доля без LLM <60% на эталонном контуре |
| R3 | Процентный сэмпл на огромных таблицах CH дорог | M/M | `SAMPLE`-клаузы где возможно, `max_rows`, профили quick/deep, маркировка «медленного» пути в UI | Backend | Скан таблицы >10 мин в эталонном контуре |
| R4 | Утечка данных через LLM (репутационная/регуляторная) | M/H | ADR-0010 (маскирование), изоляционные тесты в CI, `offline`/allowlist, опция полностью локального контура | Security-ревьюер каждого релиза | Новый агент в реестре без прохождения `agent-check --isolation` |
| R5 | Нестабильность формата ответа LLM | H/M | JSON-schema в `response_format`, repair-retry, валидация enum, мониторинг «лейбл вне таксономии» | Backend | >2% невалидных ответов в `agent_calls` за скан |
| R6 | Промпт-дрейф при смене моделей/правок | M/M | Промпты версионируются (`prompts/vN`), eval-прогон обязателен на каждое изменение (CI-ворота) | Tech Lead | Изменение файлов `prompts/` без отчёта evals/ |
| R7 | Лицензионные риски портируемых матчеров (angryscan — Apache-2.0, NOTICE; Hawk-Eye — идеи только) | L/H | NOTICE в репозитории; `go-licenses` в CI с бан-листом; запрет копирования кода Hawk-Eye | Tech Lead | Появление новой зависимости/порта |
| R8 | Полиморфизм Mongo ломает классификацию (mixed-типы) | M/M | Правила п. 8 (mixed → LLM/ревью), тесты на полиморфные фикстуры | Backend | Доля mixed-колонок >15% в тестовом контуре |
| R9 | Backlog ручного ревью растёт быстрее скорости разбора | M/M | risk-first сортировка, bulk-действия в UI, авто-подстройка порогов (v2) | Product | pending >500 вердиктов на источник |
| R10 | Зависимость от одного LLM-провайдера (цена/доступность) | M/M | OpenAI-совместимый интерфейс = смена агента — правка YAML; поддержка ≥2 провайдеров в конфиге демо | Tech Lead | Рост цены/отзыв модели заказчиком |
| R11 | Недоступность Vault блокирует старт сканирования (если используется) | L/M | Кэш последнего лиза в памяти до истечения; retry с backoff; режим деградации — fail конкретного источника, не всего скана; документированный runbook | Backend | Скан источника с Vault не стартует: 2 подряд |
| R12 | Скан деградирует продуктивную БД (latency аналитики растёт во время скана) | M/H | Resource governance (п. 13.2): лимиты на источник, circuit breaker, окна сканирования; `secondaryPreferred` для Mongo; readonly-профиль CH с лимитами ресурсов; маркировка медленных путей (п. 9) | Backend | p95 latency источника растёт на сканах в эталонном контуре |

## 19.1 Что предусмотреть до старта разработки

Обязательные организационно-технические решения до этапа 0:

1. **Источник правды по таксономии**: кто утверждает лейблы, sensitivity и alias-маппинг.
2. **Целевой профиль инсталляции**: only-local LLM / внешний провайдер / смешанный режим.
3. **Окно эксплуатации**: где будет храниться SQLite, кто делает backup, кто проверяет restore.
4. **Ролевую модель**: достаточно ли только `admin/viewer`, либо нужен `reviewer` как отдельная роль.
5. **Политику релизов**: cadence, кто утверждает bump `detectors_version` и `prompt_version`.
6. **SLO/поддержку**: кто реагирует на `budget_exceeded`, `llm_unavailable`, разрыв audit hash-chain.
7. **Границы ответственности**: что на стороне продукта, а что обязан обеспечить контур
   инсталляции (TLS, шифрование тома, reverse-proxy, IdP, Vault, SIEM).
8. **Эталонный датасет для eval**: кто владелец, как он пополняется, как размечается
   ground truth, как исключается leakage production-данных в тестовый набор.

## 20. Вне скоупа (явно не строим в этом продукте)

- Анонимизация/маскирование данных как продуктовая фича (Presidio-anonymizer,
  Skyflow, Gretel — смежная категория).
- DLP-блокировки, remediation, оркестрация доступов (Varonis-профиль).
- Файловые/S3-сканеры, OCR.
- Обучение собственных ML-классификаторов; дообучение на ревью (v2+ кандидат).
- Многофакторная авторизация (MFA обеспечивается самим IdP — вне нашего скоупа),
  мультитенантность (enterprise-v2).
- Англоязычный UI (русский — целевой; лейблы и reason_ru — по таксономии).
- Высокодоступная (multi-node) конфигурация: продукт single-instance by
  design (ADR-0006, п. 15.1); HA — через слой PostgreSQL-хранилища в v2+.
- Пользовательские override-правила классификации («колонка X всегда
  лейбл Y») и импорт существующих разметок (bootstrap из CSV) — кандидаты v2.
- Webhook-уведомления о завершении скана (Slack, e-mail) — v2; в v0.1 —
  встроенный алертинг (п. 17) и SIEM-sink (п. 14.2).
- OpenAPI-спецификация REST — v2 (в v0.1 контракт — таблица п. 11.2).

## 21. Этапы и оценки

Команда: **2 разработчика** (1 senior — архитектура/Agent Proxy/ensemble,
1 middle — коннекторы/UI). Если 1 разработчик — умножать на ~1.7.

| # | Этап | Состав | Срок |
|---|---|---|---|
| 0 | Скелет и контракты | Модуль, структура пакетов (п. 4), типы п. 5, конфиг+валидация, Makefile, CI-ворота, docker-compose окружение | 1 нед |
| 1 | **Вертикальный срез** | ClickHouse-коннектор → сэмплер → слои 0–1 (email/phone/INN/Luhn) → SQLite → консольный отчёт. End-to-end без LLM | 1.5 нед |
| 2 | MongoDB + контрактные тесты | Флаттенинг/массивы/полиморфизм (п. 8), `conftest` против обеих БД (п. 16.2) | 1.5–2 нед |
| 3 | Regex-слой полный | Порт RU-матчеров (NOTICE), IBAN/IP/даты/UUID, словари имён RU/EN, золотые вектора | 1.5–2 нед |
| 4 | LLM-слой (ядро) | Agent Proxy: изоляция, маскирование, кэш, лимиты/бюджет; YAML-реестр; ансамбль+эскалация; изоляционные тесты; fake-LLM; `agent-check` | 3 нед |
| 5 | Store + API + веб-UI + SSO + аудит | Схема БД, миграции, REST (п. 11.2), все страницы UI (п. 11.3), дрейф, экспорт; SSO SAML 2.0 (ADR-0011: crewjam/saml, роли, JIT, SLO, Keycloak в compose, п. 16.5); аудит-канал (ADR-0013: `audit_log`, hash-chain, `/audit`, API-токены) | 3.5 нед |
| 6 | Качество и экономика | Генератор датасета, eval-harness, F1 по типам, sweep порогов, отчёт $/1000 колонок, наблюдаемость | 1.5–2 нед |
| 7 | Харденинг и релиз v0.1 | Security-чеклист (п. 14), Vault на демо-контуре (ADR-0012), backup/restore + `doctor` (п. 15.2–15.3), подпись релиза, документация эксплуатации, smoke-чек, тег v0.1 | 1.5 нед |

**Итого MVP: ~15–18 недель** при команде из 2 (с учётом SSO/аудит/Vault,
ADR-0011–0013). Точка раннего сигнала: конец этапа 1 (~3-я неделя) —
если срез не прошёл, план не продолжаем без разбора.

Принцип: горизонтальные слои внутри этапов, но каждый этап заканчивается
работающим артефактом (DoD ниже), а не «готовой библиотекой без пользователя».

## 22. Критерии готовности (DoD)

**DoD каждого этапа**: CI зелёный (линт, race, ворота п. 16.7), новые пакеты
покрыты тестами согласно пирамиде, README/дока обновлены, демо на compose.

**DoD MVP (релиз v0.1)**:

- Один YAML-конфиг → скан ClickHouse + MongoDB, стратифицированный сэмпл,
  каскад 0→1→2→ensemble, чекпоинты и `--resume`.
- Веб-UI: список сканов, таблица вердиктов с фильтрами и маскированными
  примерами, очередь ревью с действиями и аудитом, страницы дрейфа и стоимости,
  экспорт CSV/JSON.
- Вход в веб-UI по **SSO SAML 2.0** (демо — Keycloak в compose): роли admin/viewer,
  JIT-прvisioning, аудит ревью привязан к SSO-пользователю; аварийный admin-токен
  проверен.
- **Журналирование и аудит**: все события из п. 14.2 пишутся в append-only
  `audit_log` с hash-chain; страница `/audit` работает; redact-тест логов
  (ни одного секрета/PII в логах) зелёный; операционные логи в JSON с
  correlation id; Vault-резолвер секретов проверен на демо-контуре.
- Изоляция LLM подтверждена авто-тестами; секреты только через env.
- Эталонный контур (compose): F1 структурных типов (PHONE, EMAIL, CARD, ИНН,
  СНИЛС, паспорт, счета) ≥0.97; доля колонок без LLM ≥70%;
  стоимость ≤$0.10/1000 колонок при внешнем агенте (или эквивалент локально).
- F1 семантических типов (PERSON_NAME, ADDRESS, FREE_TEXT, GEO_LOCATION)
  на эталонном датасете ≥0.75 (порог риска R1).
- Учебное восстановление из бэкапа (п. 15.2) успешно: hash-chain аудита
  сходится, `zond doctor` на эталонном контуре — все проверки OK.
- `make smoke` с нуля на чистой машине ≤15 минут до первых вердиктов.

## 22.1 Runbook / SRE-готовность

К релизу v0.1 кроме кода должны существовать короткие операционные runbook-документы:

- **Скан завис на `running`**: как проверить writer-очередь, LLM semaphore,
  доступность источника, состояние scheduler и audit writer.
- **Массовый рост `pending`**: как понять, это drift данных, деградация агентов,
  ошибка новой версии `detectors.yaml` или проблема mask-profile.
- **`llm_unavailable` / рост retry**: как перевести источник в offline/local-only
  режим и безопасно продолжить скан.
- **Проблемы с SSO**: fallback-процедура, как временно включить admin-token,
  как отследить все входы за период деградации IdP.
- **Разрыв hash-chain аудита**: как заморозить инстанс, снять forensic backup,
  сверить последний валидный `seq`, проверить внешний sink.
- **Restore из backup**: пошаговая процедура восстановления + проверка целостности
  `audit_log`, `verdicts`, `agent_calls`, конфигов и версии бинарника.

Эти runbook'и не обязаны быть сложными, но их наличие — часть эксплуатационной
готовности, а не «документация когда-нибудь потом».

## 23. Глоссарий

- **Слои 0–3** — этапы каскада: метаданные / regex+checksum / LLM / ансамбль.
- **Серая зона** — диапазон уверенности, при котором колонка отправляется агенту
  (`confidence_band`, default [0.30, 0.70]).
- **Вердикт** — атомарный результат классификации одной колонки/пути (п. 5.4).
- **Отпечаток (fingerprint)** — хэш от нативного типа + распределения значений;
  основа кластеризации колонок и ключа кэша.
- **Кластер колонок** — группа колонок с одинаковым отпечатком; классифицируется
  представитель, вердикт распространяется.
- **Дрейф схемы** — различия между сканами одного источника: новые/исчезнувшие
  колонки, смены лейблов/уверенности.
- **DSPM** — Data Security Posture Management (категория рынка, п. приложения А).
- **PII/PCI/PHI** — персональные / платёжные / медицинские данные.
- **EDM** — Exact Data Match, классификация точным совпадением со справочником
  (идея v2, recognizer типа `exact_dictionary`).
- **Agent Proxy** — единственная точка вызова LLM (п. 10).
- **SSO (SAML 2.0)** — вход в веб-UI через корпоративный IdP; система выступает
  SAML Service Provider (ADR-0011, п. 11.3).
- **Аудит-лог (security audit log)** — append-only журнал всех действий
  (UI/API/CLI/агенты) с цепочкой хэшей и опциональным sink в SIEM (ADR-0013,
  п. 14.2).
- **Vault (HashiCorp Vault)** — внешнее хранилище секретов; опция получения
  секретов подключений к БД с динамической ротацией и без их хранения на
  сервере (ADR-0012, п. 12.1).
- **Evidence** — маскированные примеры и технические детали решения слоя.
- **Верификатор** — второй агент в режиме подтверждения/отклонения
  кандидатных лейблов при эскалации (п. 5.3, 7).
- **Preflight (`doctor`)** — команда проверки готовности инсталляции
  перед вводом в эксплуатацию (п. 15.3).
- **Resource governance** — лимиты нагрузки сканера на источники БД
  (п. 13.2).
- **Retention** — сроки хранения данных продукта (п. 15.4).

## 24. Smoke-сценарий «одна команда»

```bash
git clone <repo> && cd zond
make smoke        # build + подъём compose (app, CH, Mongo, seed)
# → seed наполняет CH/Mongo демо-данными (вкл. РФ-форматы)
# → app выполняет quick-скан обоих источников
# → http://localhost:8080  — UI с вердиктами (логин: admin-токен из .env)
make eval         # эталонный датасет + отчёт F1 и $/1000 колонок
```

## 25. Changelog

- **2026-10-17, v2**: документ собран как единый источник правды. Изменения
  относительно анализа в `./анализ`: язык — Python → **Go** (ADR-0001);
  Presidio → собственный движок слоя 1 с портом RU-матчеров (ADR-0002);
  локальный NER вынесен в v2 (ADR-0003); добавлены: веб-UI (ADR-0007),
  контракты как код (п. 5), таблица ошибок (п. 6), семантика confidence (п. 5.6),
  специфика Mongo/CH (п. 8–9), безопасность системы (п. 14), тест-стратегия
  и eval-harness (п. 16), NFR (п. 18), реестр рисков (п. 19), DoD (п. 22),
  вертикальный срез первым этапом разработки (п. 21).
- **2026-10-17 (доп. к v2)**: добавлена обязательная интеграция **SSO SAML 2.0**
  для веб-UI (ADR-0011; п. 3, 4, 11.1, 11.3, 12, 14, 16, 20, 22, 23): библиотека
  `crewjam/saml`, роли admin/viewer из SAML-атрибута/групп, JIT-прvisioning,
  admin-токен переведён из основного метода входа в аварийный fallback;
  SSO исключён из «вне скоупа» (п. 20).
- **2026-10-17 (доп. 2)**: добавлены **ADR-0012** (HashiCorp Vault: динамические
  секреты БД без хранения на сервере, п. 12.1) и **ADR-0013** (два канала
  журналирования: операционные JSON-логи с redact и append-only аудит действий
  с hash-chain + SIEM-sink, п. 14.1–14.2). Усилена безопасность (п. 14):
  защита audit-лога, rate-limit на fallback-логин, CSRF/флаги cookie,
  anti-replay SAML, защита от prompt injection через значения БД, govulncheck
  и SBOM в CI, харденинг контейнера, контроль экспорта, API-токены со scope;
  обновлены п. 11.2, 15, 16.7, 22, 23.
- **2026-10-17 (доп. 3, ревью перед стартом разработки)**: план (п. 21) —
  работы SSO/аудит распределены в этап 5, Vault/backup/doctor — в этап 7,
  итог MVP пересчитан ~15–18 нед; исправлена ссылка на кластеризацию
  (новый п. 7.6). Таксономия (п. 5.5): служебные лейблы DATE_TIME,
  BOOLEAN, JSON_DOC; semver-правила и alias-маппинг при major. `verdicts`
  (п. 5.4): поля `taxonomy_version`, `detectors_version`, `prompt_version`.
  Ансамбль (п. 7): псевдокод, множественные матчеры, tie-break; п. 7.6 —
  состав fingerprint и кластеризация; п. 5.6 — таблица источников
  confidence; п. 5.3 — структура вызова и схема ответа верификатора;
  правило small_sample (п. 6, 7). Новое: ADR-0014 (single-instance + WAL +
  горячая перезагрузка `detectors.yaml`, п. 12); resource governance
  (п. 13.2); процессная модель (п. 15.1); backup/restore (п. 15.2);
  preflight `doctor` (п. 15.3); retention (п. 15.4); RBAC-матрица (п. 11.3);
  маск-профиль (п. 10.2); сложные типы ClickHouse (п. 9); канонический
  формат `audit_log` и жизненный цикл API-токенов (п. 14.2); физические
  правила SQLite (п. 11.1). Безопасность (п. 14): XSS/CSP, SSRF-дефолт
  allowlist (п. 10.7), подпись релизов; алертинг (п. 17); лимиты экспорта
  и rate-limit API (п. 11.2); SSO-эксплуатация (п. 11.3). Тесты (п. 16):
  bench, fuzz, тест миграций. Риски: добавлен R12. Скоуп (п. 20): HA,
  override-правила, webhooks, OpenAPI — явно вне. DoD (п. 22): F1
  семантики ≥0.75, восстановление из бэкапа, `doctor`. Постановка (п. 1):
  регуляторный контекст 152-ФЗ; глоссарий — дополнен.
- **2026-10-17 (доп. 4)**: добавлен производный рабочий документ
  `architecture.md` (модель реализации: архитектурный стиль, слои и правила
  зависимостей, потоки исполнения, механизмы, карта пакетов, деплой-вид,
  анти-архитектура, traceability этапов). Содержание blueprint не изменено;
  источник правды — по-прежнему этот файл.
- **2026-10-18 (доп. 6)**: рабочее имя артефакта изменено `classifier` → **`zond`**
  (механическая замена, разрешённая п. 3): пп. 1, 3, 4, 15, 21, 23, 24; в примерах
  конфигов id агентов — `zond-main`/`zond-strong`. Этап 0 реализован (модуль
  `github.com/DunchikVlad/zond`, см. docs/progress/2026-10-18-stage-0.md).
- **2026-10-18 (доп. 5)**: усилены эксплуатационные и governance-аспекты:
  добавлены правила версионирования API/конфигов/миграций (п. 18.1),
  privacy/data governance (п. 18.2), обязательный список решений до старта
  разработки (п. 19.1) и требования к runbook / SRE-готовности (п. 22.1).

## Приложение А. Что взято из анализа (`./анализ`)

| Идея-источник | Где принята |
|---|---|
| Каскад возрастающей стоимости (Varonis, Cyera, Teleskope, Ethyca) | п. 1, 7 |
| Слой 0 — классификация по метаданным до значений (Ethyca) | п. 7 (детерминированный в MVP) |
| LLM как верификатор кандидатов, эскалация (Cyera) | п. 5.3, 7.4 |
| Маскирование перед отправкой агенту (Teleskope) → усилено до ADR-0010 | п. 10, 11, 14 |
| Сэмплирование как рычаг стоимости, профили (AWS Macie) | п. 5.2 |
| Кластеризация колонок по отпечатку (Cyera, BigID) | п. 7, 10 |
| Очередь ручного ревью и петля обратной связи (Purview) | п. 11.3, 17 |
| SPI по референсу OpenMetadata, конвенция путей | п. 4, 5.1 |
| Порт RU-матчеров (angryscan-core, Apache-2.0 + NOTICE) | п. 3 (ADR-0002), 16 |
| Разделение конфигов connections/detectors (Hawk-Eye, только идеи) | п. 12 |
| Дрейф схемы (Databricks LogSentinel) | п. 11.1, 11.3 |
| Экономика-ориентир $0.60/1000 полей «голого» LLM (Ethyca) | п. 22 (цель ≤$0.10 с каскадом) |

## Приложение Б. Лицензии

1. **angryscan-core (Apache-2.0)** — порт матчеров допустим; файл NOTICE с
   указанием источника обязателен в репозитории и в дистрибутиве.
2. **Hawk-Eye (LGPL 2.1 + Commons Clause)** — только идеи (паттерн конфигов),
   код и формулировки не копируются.
3. Go-зависимости — MIT/BSD/Apache-2.0; `go-licenses` в CI с бан-листом
   (GPL*, Commons Clause, CC-BY-NC).
4. Для v2 (ONNX-модели) — проверка карточки конкретной ревизии модели на HF
   (встречается CC-BY-NC — для коммерции не подходит).
