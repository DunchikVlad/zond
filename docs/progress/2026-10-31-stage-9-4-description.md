# S9-4 — отдельный агентский прогон описания БД (DescriptionRunner)

Дата: 2026-10-31. Инкремент: S9-4.

## Основание

- План S9: `docs/progress/2026-10-25-stage-9-plan.md` §5 (S9-4).
- HANDOFF: «Следующий шаг S9-4: DescriptionRunner — отдельный агентский прогон описания БД по scan_id».
- Blueprint: п. 10 (Agent Proxy), п. 11 (Verdict Store, REST API, веб-UI), п. 14 (аудит).
- ADR-security-llm-isolation: контур данных описания — агрегированные вердикты без сырых значений.

## Реализация

### Миграция 0013 — description_runs

```sql
CREATE TABLE description_runs (
    id              TEXT PRIMARY KEY,
    scan_id         TEXT NOT NULL REFERENCES scans(id),
    status          TEXT NOT NULL CHECK (status IN ('running','done','failed','interrupted')),
    prompt_version  TEXT NOT NULL DEFAULT '',
    prompt_hash     TEXT NOT NULL DEFAULT '',
    agent_id        TEXT NOT NULL DEFAULT '',
    model           TEXT NOT NULL DEFAULT '',
    tokens_in       INTEGER NOT NULL DEFAULT 0,
    tokens_out      INTEGER NOT NULL DEFAULT 0,
    cost_usd        REAL NOT NULL DEFAULT 0,
    latency_ms      INTEGER NOT NULL DEFAULT 0,
    result_json     TEXT NOT NULL DEFAULT '',
    error           TEXT NOT NULL DEFAULT '',
    created_at      TEXT NOT NULL,
    finished_at     TEXT
);
```

Индексы: `idx_description_runs_scan`, `idx_description_runs_status`.
Retention — вместе со сканом (FK на scans).

### Промпт — prompts.DescriptionVersion = "1"

Отдельная версия от классификатора/верификатора. System-промпт: аналитик БД,
строгая JSON-схема ответа (7 обязательных полей), анти-инъекция через `<data>`.
User-промпт: `<data>` + агрегированный JSON вердиктов. Схема:
- `purpose_ru` (10–500 символов) — назначение БД;
- `table_groups` — группы таблиц с описанием;
- `data_categories` — категории данных;
- `sensitivity_zones` — pii/pci/phi/none таблицы;
- `risks` — риски;
- `ambiguities` — неоднозначности;
- `review_recommendations` — рекомендации по ревью.

### agentproxy.Describe

Новый метод поверх того же транспорта (OpenAI-compat chat completions).
Аналогично Classify/Verify: gate (семафор+rate-limit), egress-политика,
ретраи на невалидный JSON, валидация схемы (purpose_ru 10–500, table_groups
и data_categories непустые). Usage/Latency — для учёта экономики.

### scanengine.DescriptionRunner

Оркестратор: агрегация вердиктов скана (только лейблы/типы/sensitivity/
confidence — без сырых значений), вызов LLM, фиксация статуса/экономики/аудита.

- Требование: скан в терминальном статусе (done/partial/failed/budget_exceeded);
- partial — с пометкой PARTIAL_SCAN во входе LLM;
- аудит: description_start (до вызова, fail-closed), description_finish (после),
  description_failed (при ошибке); actor — из контекста вызова;
- стоимость по прайс-листу model_prices;
- ошибка LLM — статус failed, текст ошибки (≤300 символов) в description_runs.error.

### REST API (v1)

| Метод | Путь | RBAC | Назначение |
|---|---|---|---|
| POST | `/api/v1/scans/{id}/description-runs` | ActionScan | запуск описания |
| GET | `/api/v1/scans/{id}/description-runs` | ActionView | история прогонов |
| GET | `/api/v1/description-runs/{id}` | ActionView | карточка прогона |

Ошибки: 404 (скан/прогон не найден), 409 (не терминальный статус), 501 (LLM
не подключён). Ответ — DTO с полями description_runs; result_json отдаётся
как объект (не строка).

### Web UI

- Кнопка «Описание БД» на /scans/{id} для терминальных статусов (POST /scans/{id}/describe);
- Таблица истории прогонов описания: статус, версия промпта, агент/модель,
  токены, стоимость, timestamps; раскрытие результата (details/summary);
- Экранирование через html/template (стандартное, без safeHTML).

### Подключение в serve

При `-llm` и непустом реестре agents: `buildDescriptionRunner` создаёт
`scanengine.DescriptionRunner` с первым агентом реестра. Без LLM — runner nil,
UI/API возвращают 501.

## Проверки

- `make ci` (fmt + vet + build + test) — зелёный;
- `go test -race ./internal/scanengine/... ./internal/api/... ./internal/verdict/store/... ./internal/audit/...` — зелёный;
- миграции up/down/up — зелёные (TestMigrationsUpDownUp);
- unit-тесты: store CRUD (2 теста), agentproxy Describe (4 теста),
  scanengine DescriptionRunner (8 тестов), API handlers (9 тестов).

## Ограничения и открытые вопросы

- Живой стенд не запускался (LLM — fake в тестах; Kimi ждёт пополнения);
- Агрегированный вход — только лейблы/типы/sensitivity; имена таблиц/колонок
  в LLM — контур зафиксирован для пересмотра в ADR изоляции (отдельный шаг);
- Retention описаний — вместе со сканом (FK); отдельного TTL нет;
- Отмена running-описания не реализована (sync-вызов, короткий);
  interrupted — только по ctx-отмене (таймаут агента).
