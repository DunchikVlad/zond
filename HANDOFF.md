# HANDOFF — документ передачи между агентами

Это «живой» документ. Каждый агент, заканчивая сессию, ОБЯЗАН обновить
раздел «ТЕКУЩЕЕ СОСТОЯНИЕ» и пройти «ЧЕК-ЛИСТ ПЕРЕДАЧИ» — и только потом
передавать файл следующему агенту. Стабильные разделы (1–5) меняй только
при реальном изменении проекта, конвенций или окружения.

Промт для нового агента — весь этот файл целиком, от начала до конца.

---

## 1. Проект

«zond» — классификатор чувствительных данных (PII) в БД (ClickHouse,
MongoDB): regex-правила + LLM-ансамбль через agent-proxy с egress-политикой
и бюджетом, вердикты в SQLite (goose-миграции), аудит-лог с hash-chain
(append-only), REST API v1, веб-UI, SSO (SAML SP) + RBAC, API-токены.
Разработка ведётся инкрементами по `blueprint.md` (v2) с фиксацией каждого
шага в `docs/progress`, `docs/validation`, `docs/security`, `docs/decisions`.

## 2. Окружение и запуск

- Репозиторий: локальная копия `DunchikVlad/zond`, ветка `main`.
- ОС: Windows, работа через Git Bash. `go` может отсутствовать в PATH —
перед сборкой найди toolchain (проверь стандартные пути, `where go`).
- Стек: Go; SQLite; cobra CLI; crewjam/saml; robfig/cron/v3.
- Команды: `make ci` (fmt + vet + build + test) — обязательный прогон
  перед коммитом; `make test-race`, `make config-check`; `make lint`
  (нужен локальный golangci-lint). CI-ворота: `.github/workflows`.
- Конфиги без секретов: `configs/connections.yaml`; секреты через ENV,
  фиктивные значения для проверок — `configs/ci.env`.
- Тестовые стенды БД: в `configs/connections.yaml` (внешние хосты
  192.168.31.119 и keycloak-стенд `deploy/docker-compose.keycloak.yml`);
  недоступность стенда ≠ поломка кода — различай.

## 3. Карта документов (читать перед работой)

1. `blueprint.md` — требования и план (п. 11 store/API/UI, 14 безопасность,
   15 деплой/retention/процессы, 16 тестирование, 17 метрики).
2. `architecture.md` — архитектура.
3. `docs/progress/` — журнал инкрементов (начинай с последних по дате).
4. `docs/decisions/` — ADR и ADR-impl (обязательны к прочтению затрагиваемые).
5. `docs/security/`, `docs/validation/` — артефакты приёмки инкрементов.
6. `git log --oneline -30` — гранулярность и стиль коммитов.

## 4. Конвенции проекта

- Инкременты помечаются S0, S1, … S5а, S5б, S5в, S5г … Коммит одного
  инкремента = код + тесты; документация — отдельным коммитом с суффиксом
  «-док». Префикс коммита = метка инкремента, текст на русском.
- Закрыв инкремент (код + «-док»), агент пушит `main` в `origin`
  (`github.com/DunchikVlad/zond`) и проверяет `git status -sb`: ветка
  не должна быть ahead/behind (требование пользователя, с 2026-10-21).
- Каждый инкремент обновляет: `docs/progress/<дата>-<инкремент>.md`,
  `docs/validation/`, `docs/security/`, при архитектурном решении —
  `docs/decisions/ADR-impl-*.md`.
- Не смешивать разные инкременты в одном коммите.
- Миграции goose — только добавляющие, нумерация сквозная (`migrations/`).
- depguard (`.golangci.yml`): `net/http` разрешён только в явно перечисленных
  пакетах (`internal/api`, `internal/auth`, `cmd`, …). Новая точка входа
  по HTTP = осознанное обновление списка.
- Аудит: все пользовательские и фоновые действия — в audit-лог с actor;
  экспорт данных аудируется ДО выдачи; фоновые задачи — actor `scheduler`.
- Fail-closed по безопасности: при сомнении запрещай, а не разрешай
  (см. ADR-security-llm-isolation).

## 5. Правила работы агента

1. Verify-first: перед любой правкой добейся зелёного `make ci` на
   текущем дереве; сломанное состояние фиксируй в разделе 6, а не чини
   молча «по пути».
2. Изменения — точечно, в рамках текущего инкремента; рядом лежащее
   «неидеальное» не рефакторь без запроса.
3. Ничего не коммить, пока не прогнал `make ci` (и `make test-race`,
  если трогал конкурентность).
4. Факты из документов > предположения из памяти; устаревшее в документах
   — исправляй в рамках «-док» коммита.
5. Перед передачей — обновить раздел 6 и пройти чек-лист раздела 7.

## 6. ТЕКУЩЕЕ СОСТОЯНИЕ (обновляется каждым агентом)

Снимок от 2026-11-01 ~13:30 UTC (сессия S9-8; код `b3c0427`,
документация этим «-док» коммитом):

- **S9-8 завершён и ПРОВЕРЕН НА СТЕНДЕ**: фиксы замечаний З1/З2 из
  протокола 2026-11-01.
  - З1: `ListTables` ClickHouse — `lower(database)` при исключении
    system/information_schema (CH 26.x держит uppercase-копию). На стенде:
    скан ch-test — 1 таблица, 5 вердиктов (было 21/489).
  - З2: при `sso.enabled=false` теперь обязателен `CLASSIFIER_ADMIN_TOKEN`
    (blueprint п. 12): API — 401 без/с неверным токеном; UI — 302 на новый
    `/login` (форма → сессия admin, constant-time, brute-force блокировка
    AttemptLimiter, аудит admin_token_used/login_failure); serve fail-fast
    без токена (код 2). rate-limit S9-6 заработал (burst → 226×429).
    smoke-compose получил CLASSIFIER_ADMIN_TOKEN (zond-smoke-admin).
    dev-режим без токена/SSO (тесты) не изменён.
  - Тесты: api TestAdminTokenOnlyMode/TestNoAuthDevMode; web login_test.go
    (закрытость страниц, флоу логина, 429, dev-режим). `go test ./...`
    зелёный; `go test -race` (api/web/clickhouse) — на стенде Linux
    (gcc доустановлен deb'ами через scp; toolchain go1.27.3 + vendor в
    /tmp/gotc, /tmp/zond-src) зелёный. На Windows race недоступен (нет gcc).
  - Подробности: `docs/progress/2026-11-01-stage-9-8-stand-fixes.md`,
    протокол — `docs/validation/2026-11-01-stand-deployment.md` п. 5.
- **Следующий шаг**: по плану S9-7 (качество, CI, лицензии, документация);
  открытые З3–З6 (Windows-тесты agentproxy, сеть стенда, устаревший
  compose-stand, LLM-контур без ключа).
- Открытое (без изменений): Kimi живой прогон ждёт баланса/ключа; fake-LLM
  eval $0,117/1000 выше цели $0,10; CI Fuzz/coverage gate не добавлены
  (PAT без `workflow`); LICENSE/NOTICE отсутствуют; flaky race audit.

Снимок от 2026-11-01 ~08:30 UTC (сессия: пересборка стенда на Debian 13;
код `76e1629`+`635ec4a`, документация этим «-док» коммитом):

- **Новый стенд развёрнут с нуля и проверен**. Адреса (прежние
  .113/.119 выведены): приложение — **192.168.31.248** (`/opt/zond/{bin,
  configs,data,zond.env}`, systemd `zond.service`, UI 0.0.0.0:8080),
  БД-источники — **192.168.31.64** (ClickHouse 26.9.9.28, MongoDB 8.0.34,
  PostgreSQL 17.11 — новый источник `pg-test`). ОС Debian 13 (trixie),
  AMD Ryzen 7 7700 (AVX2 — ограничения старого стенда сняты), Docker нет.
  SSH `test@test`/`test`, sudo NOPASSWD. Подробности:
  `docs/progress/2026-10-18-test-environment.md` п. 9.
- connections.yaml: ch-test/mongo-test → .64, добавлен pg-test;
  ci.env += PG_TEST_PASSWORD. Сборка v0.1-38-gd27576b-dirty-stand
  задеплоена. LLM не настроен (KIMI_API_KEY на стенде нет).
- **Тестирование** (протокол `docs/validation/2026-11-01-stand-deployment.md`):
  doctor — 3 тестовых источника OK; сканы ch/mongo/pg — done (PostgreSQL
  коннектор S9-5 впервые живьём); API/UI/ревью/дрейф/экспорт/аудит
  (hash-chain OK)/бэкап — зелёные; resume done-скана и description-runs
  без LLM корректно отклоняются.
- **Замечания** (полный текст в протоколе):
  - З1 (баг): ClickHouse 26.x — ListTables сканирует `INFORMATION_SCHEMA`
    (uppercase): фильтр `connector.go:43` регистрозависим → 21 таблица,
    489 шумовых вердиктов (64 ложных PERSON_NAME PII). Фикс: `lower(database)`.
  - З2 (безопасность): при `sso.enabled: false` аутентификация отключена
    полностью — API/UI отдают 200 без токена и с неверным токеном
    (blueprint п. 12 обещает «только admin-токен»); rate-limit S9-6 в этом
    режиме не действует (500 rps-burst → все 200).
  - З3: 3 теста agentproxy (Latency>0) падают на Windows (гранулярность
    таймера), на Linux зелёные — `make ci` на Windows красный из-за этого.
  - З4: сеть стенда до внешних CDN 10–15 КБ/с, apt зависает — софт
    ставить скачиванием deb на машине разработчика + scp + dpkg -i.
  - З5: `deploy/docker-compose.stand.yml` устарел (старый стенд, mongo:4.4).
- **Следующий шаг**: решения по З1/З2 (фиксы за следующим инкрементом/
  владельцем); далее по плану S9-7 (качество, CI, лицензии).
- Открытое (без изменений): Kimi живой прогон ждёт баланса/ключа; fake-LLM
  eval $0,117/1000 выше цели $0,10; CI Fuzz/coverage gate не добавлены
  (PAT без `workflow`); LICENSE/NOTICE отсутствуют; flaky race audit.

Снимок от 2026-10-31 ~16:00 UTC (сессия S9-6; код — этот коммит,
документация этим «-док» коммитом):

- **S9-6 завершён**: оставшиеся продуктовые доработки.
  - **Per-profile сэмплирование** (quick/deep/custom): `ScanConfig` получил
    `Quick`/`Deep` `SampleConfig`; `config.SampleForProfile()` — выбор по
    профилю, merge непустых полей поверх default. `engineConfig` использует
    `config.SampleForProfile`. detectors.yaml: quick (1%, 5k rows, 100 chars),
    deep (10%, 50k rows, 500 chars). Валидация per-profile в `Validate()`.
  - **API rate-limit** (п. 11.2): `api.RateLimiter` — token-bucket по субъекту
    (actor), default 100 req/s. Подключён в `withAuth` после успешной
    аутентификации. 429 при превышении. Тесты: 5 кейсов.
  - **UX**: keyboard shortcuts y/n/l для ревью (vanilla JS, первая карточка);
    скрытие admin-ссылок (audit/settings/sources) и admin-действий
    (stop/resume/describe) у viewer в шаблонах.
  - Подробности: `docs/progress/2026-10-31-stage-9-6-ux.md`.
- Проверки: исходный и финальный `make ci`, `go test -race` (config, api,
  web) — зелёные.
- **Следующий шаг S9-7**: качество, CI, лицензии, документация (живой Kimi
  eval, coverage gate, LICENSE/NOTICE, flaky audit race).
- Открытое: Kimi живой прогон ждёт пополнения баланса; fake-LLM eval
  $0,117/1000 выше цели $0,10. CI Fuzz/coverage gate не добавлены (PAT без
  `workflow`), LICENSE/NOTICE отсутствуют; flaky race audit не проявился.

Снимок от 2026-10-31 ~14:00 UTC (сессия S9-5; код `6fd2483`,
документация этим «-док» коммитом):

- **S9-5 завершён**: выбор СУБД и новый коннектор PostgreSQL.
  - `internal/connector/postgres/`: коннектор PostgreSQL (lib/pq, pure Go):
    Ping, ListTables (information_schema), GetSchema (unwrap типов),
    CountRows, Sample (ORDER BY random()), классификация ошибок (pq коды
    53300/53400/57P01/57P02/57P03/58030 + сетевые) → retryable/overload.
    Регистрация в init() как "postgresql".
  - Динамический список типов: `connector.Types()` вместо hardcoded
    clickhouse|mongodb в UI (`/sources` select) и валидации (`sourceedit.go`).
    Единая проверка type/DSN/URI/ref: postgresql — dsn (uri неприменим).
  - Тесты: contract_test (testcontainers postgres:16-alpine, пропуск без
    Docker), errors_test (7 кейсов классификации).
  - Подробности: `docs/progress/2026-10-31-stage-9-5-postgres.md`.
- Проверки: исходный и финальный `make ci`, `go test -race` (connector,
  config, web) — зелёные. Контрактные тесты PostgreSQL скипнуты без Docker
  (testcontainers), unit-тесты зелёные.
- **Следующий шаг S9-6**: оставшиеся продуктовые доработки (quick/deep/custom
  семантика, редактирование реестра агентов, API rate-limit, async-экспорт,
  UX-улучшения).
- Открытое: Kimi живой прогон ждёт пополнения баланса; fake-LLM eval
  $0,117/1000 выше цели $0,10. CI Fuzz/coverage gate не добавлены (PAT без
  `workflow`), LICENSE/NOTICE отсутствуют; flaky race audit не проявился.

Снимок от 2026-10-31 ~12:00 UTC (сессия S9-4; код `3b88f54`,
документация этим «-док» коммитом):

- **S9-4 завершён**: DescriptionRunner — отдельный агентский прогон описания
  БД по scan_id (без повторного подключения к источнику). Миграция 0013:
  `description_runs` (id, scan_id FK, status, prompt_version/hash, agent_id,
  model, tokens, cost_usd, latency_ms, result_json, error, timestamps).
  Статусы running/done/failed/interrupted; partial-скан — с пометкой
  PARTIAL_SCAN во входе LLM. Агрегированный вход: только лейблы/типы/
  sensitivity/confidence, без сырых значений и имён инфраструктуры (ADR
  изоляции). Промпт `prompts.DescriptionVersion="1"`, строгая JSON-схема
  (purpose_ru, table_groups, data_categories, sensitivity_zones, risks,
  ambiguities, review_recommendations). `agentproxy.Describe` — новый метод
  поверх того же транспорта (OpenAI-compat), валидация схемы, ретраи.
  `scanengine.DescriptionRunner` — оркестратор: агрегация вердиктов,
  вызов LLM, фиксация статуса/экономики/аудита (description_start/finish/
  failed, actor, без текста результата в аудите). Стоимость по прайс-листу
  model_prices. API: `POST /api/v1/scans/{id}/description-runs` (ActionScan,
  409 если не терминальный), `GET /api/v1/scans/{id}/description-runs`
  (история), `GET /api/v1/description-runs/{id}` (карточка). Web: кнопка
  «Описание БД» на /scans/{id} (терминальные статусы), таблица истории
  с раскрытием результата. Подключение в serve: при -llm и непустом
  реестре agents. Подробности: `docs/progress/2026-10-31-stage-9-4-description.md`.
- Проверки: исходный и финальный `make ci`, `go test -race` (scanengine,
  api, store, audit) — зелёные. Миграции up/down/up покрыты. Живой стенд
  не запускался (LLM — fake в тестах).
- **Следующий шаг S9-5**: выбор СУБД и новые коннекторы (PostgreSQL →
  MySQL/MariaDB → MS SQL). Список типов из connector.Types(), capability-
  метаданные, единая валидация type/DSN/URI/ref.
- Открытое: Kimi живой прогон ждёт пополнения баланса; fake-LLM eval
  $0,117/1000 выше цели $0,10. CI Fuzz/coverage gate не добавлены (PAT без
  `workflow`), LICENSE/NOTICE отсутствуют; flaky race audit не проявился.

- **S9-3 завершён**: пользовательский промпт на скан. Prompt-контракт
  blueprint (п. 5.3 пользовательская инструкция, п. 10.5 хэш в ключе кэша,
  п. 11.1 колонки scans, п. 13 resume) и ADR-security-llm-isolation
  (дополнение S9-3) обновлены до кода. `prompts.Version="2"`;
  `NormalizeUser` (≤2000 рун, NUL запрет, trim), `UserHash`,
  `SystemWithInstruction`/`VerifierSystemWithInstruction` (блок
  `<operator_instruction>` после защищённых правил). Единый
  `scanengine.ScanOptions` во всех трёх интерфейсах (api/web/scheduler);
  agentproxy `WithInstruction` (system классификатора и верификатора).
  Per-scan LLM (`llm *bool` в API, select в UI, default — поведение сервера).
  Миграция 0012: `scans.prompt_base_version/prompt_hash/prompt_text/llm_enabled`;
  resume сверяет оба поля fail-closed и воспроизводит промпт+флаг исходного
  прогона (CLI `-prompt` с `-resume` отклоняется). Ключ кэша включает хэш
  инструкции — разные промпты не делят кэш. Scheduled-прогоны — всегда
  стандартный промпт. Аудит scan_start: prompt_hash/prompt_len/llm без текста.
  REST: лимит тела 1 МБ, DisallowUnknownFields. Подробности:
  `docs/progress/2026-10-26-stage-9-3-user-prompt.md`.
- Проверки: исходный и финальный `make ci`, полный `make test-race` (все
  пакеты) — зелёные. Миграции up/down/up и v11→v12 покрыты. Живой стенд не
  запускался.
- **Следующий шаг S9-4**: DescriptionRunner — отдельный агентский прогон
  описания БД по scan_id (без повторного подключения к источнику), versioned
  prompt + строгая схема, статусы running/done/failed/interrupted, история
  описаний, экономика и аудит, endpoint'ы по плану. Контур данных описания
  (имена таблиц/колонок в LLM) уже зафиксирован для пересмотра в ADR изоляции.
- Открытое: Kimi живой прогон ждёт пополнения баланса; fake-LLM eval
  $0,117/1000 выше цели $0,10. CI Fuzz/coverage gate не добавлены (PAT без
  `workflow`), LICENSE/NOTICE отсутствуют; flaky race audit в обеих сессиях
  не проявился (полный race зелёный).

Снимок от 2026-10-26 ~19:10 UTC (сессия S9-2; код `aca8cc1`,
документация этим «-док» коммитом):

- **S9-2 завершён**: полный per-column LLM evidence. Миграция 0011:
  `agent_calls` получил operation (classify|verify), answer_label/confidence/
  sensitivity, reason_ru, error (≤300 симв.); `verdicts.llm_status` (7 статусов:
  not_called/called/cache_hit/small_sample/cluster_propagated/budget_exceeded/
  error) + индекс; бэкфилл исторических строк только по фактам evidence.
  Движок выставляет статус во всех ветках каскада; ошибка верификатора статус
  колонки не меняет. Кэш-фикс: cachedLLMVerdict хранит reason_ru/sensitivity,
  при hit заполняется PromptVersion вердикта, evidence["llm"] при hit эквивалентен
  miss. Evidence расширен экономикой (tokens/cost/latency/prompt_version/agent/
  model) для classify и verify. API: фильтр `?llm_status=` (валидация, 400),
  `GET /api/v1/verdicts/{id}/agent-calls`; UI: select фильтра, колонка «LLM»,
  раскрытие «вызовы LLM» (ленивая HTMX-подгрузка /verdicts/{id}/calls).
  Экономичный каскад не изменён. Подробности:
  `docs/progress/2026-10-26-stage-9-2-llm-evidence.md`.
- Проверки: исходный и финальный `make ci`, полный `make test-race` (все
  пакеты, включая audit/scanengine) — зелёные. Миграции up/down/up и v10→v11
  с существующими данными покрыты. Живой стенд не запускался.
- **Следующий шаг S9-3**: пользовательский промпт на скан — textarea инструкции,
  единый ScanOptions, per-scan включение LLM, неизменяемый snapshot промпта,
  prompt hash в scans и в ключе кэша, аудит actor/hash/length.
- Перед S9-3/S9-4 по-прежнему обновить prompt-контракт и ADR изоляции описания.
- Открытое: Kimi живой прогон ждёт пополнения баланса; fake-LLM eval
  $0,117/1000 выше цели $0,10. CI Fuzz/coverage gate не добавлены (PAT без
  `workflow`), LICENSE/NOTICE отсутствуют; известный flaky race audit в этой
  сессии не проявился (полный race зелёный).

Снимок от 2026-10-26 ~18:10 UTC (сессия S9-1; код `691d0f4`,
документация этим «-док» коммитом):

- **S9-1 завершён**: `/sources` экранирует HTMX, полностью валидирует YAML,
  сериализует save/delete mutex'ом, использует уникальные temp, откатывает
  файл/runtime при ошибке apply/audit; Vault ref и per-source лимиты доступны
  в UI, ENV-пароль проверяется как целая ссылка. Подробности:
  `docs/progress/2026-10-26-stage-9-1-correctness.md`.
- Таблицы получили каноническое `schema.table` (Mongo `database.collection`,
  экранирование `\`/`.`). Оно проходит через checkpoint, verdict ID/store,
  drift/API/UI; одноимённые таблицы разных схем больше не перезаписываются.
- Миграция `0010_scan_provenance.sql`: table identity version + config
  fingerprint/taxonomy/detectors/binary versions. Старые строки не угадываются
  и без provenance не возобновляются. CLI `-resume` сверяет конфиг; добавлены
  REST `POST /api/v1/scans/{id}/resume` и UI-кнопки, 409 содержит все mismatches.
- Проверки: исходный и финальный `make ci`, `make config-check`, полный
  `make test-race` — зелёные (в т.ч. audit). Миграции up/down/up и v9→v10
  с существующими scan/checkpoint/verdict покрыты. Живой стенд не запускался.
- **Следующий шаг S9-2**: полный per-column LLM evidence (ответ classify/verify
  отдельно от ensemble, usage/cost/latency/status), эквивалентный cache hit/miss
  (reason/sensitivity/PromptVersion), фильтры API/UI; экономичный каскад сохранить.
- Перед S9-3/S9-4 по-прежнему обновить prompt-контракт и ADR изоляции описания.
- Открытое: Kimi живой прогон ждёт пополнения баланса; fake-LLM eval
  $0,117/1000 выше цели $0,10. CI Fuzz/coverage gate не добавлены (PAT без
  `workflow`), LICENSE/NOTICE отсутствуют; известный flaky race audit остаётся
  в списке наблюдений, хотя в этой сессии полный race прошёл.

Снимок от 2026-10-25 ~19:38 UTC (сессия планирования S9; базовый HEAD
`de8246c` = origin/main, код не менялся):

- **План S9 задокументирован**: `docs/progress/2026-10-25-stage-9-plan.md`.
  Приоритет: S9-1 исправления `/sources`, qualified `schema.table`, совместимость
  resume/provenance → S9-2 полный per-column LLM evidence и кэш → S9-3
  пользовательский prompt на скан с prompt hash/snapshot → S9-4 отдельный
  DescriptionRunner по `scan_id` → S9-5 динамический выбор СУБД и PostgreSQL →
  S9-6 профили/UI/API/async-export/rate-limit → S9-7 живой eval и CI/доки.
- Перед S9-3/S9-4 обновить blueprint/ADR: prompt-контракт и допустимый контекст
  описания БД (текущая изоляция запрещает имена БД/таблиц/хостов в LLM).
- Проверка дерева: `make ci` зелёный; coverage rules 93,6%, agentproxy 83,8%,
  ensemble 95,7%. Изменений в коде в этой сессии нет.
- Открытое: Kimi живой прогон — ждёт пополнения баланса; fake-LLM eval
  $0,117/1000 колонок выше цели $0,10. CI Fuzz и coverage gate не добавлены;
  LICENSE/NOTICE отсутствуют; известный flaky race `internal/audit` остаётся.

Снимок от 2026-10-25 ~16:20 UTC (сессия S8-8 — hot-reload detectors.yaml,
частичная реализация ADR-0014; HEAD `00c410c` = origin/main):

- **S8-8 запушен и ПРОВЕРЕН НА СТЕНДЕ** (`135a5d4` + доки `00c410c`):
  «Настройки → Детекторы» (только admin): профиль, tau_accept/tau_review,
  веса meta/rules/llm, cluster, proxy-лимиты/budget/offline — правка
  detectors.yaml через yaml.Node (комментарии сохраняются, числа не str),
  валидация Detectors.Validate, горячее применение к новым прогонам через
  bundleHot atomic swap (engineRunner читает bundle() на старте прогона).
  Живо: save tau_review=0.45/w_llm=1.35 → в файле и применено без
  рестарта; стенд откачен к исходным значениям. На .113 сборка 135a5d4.
- Вне скоупа (рестарт): реестр агентов (egress/endpoint/кэш-ключи),
  taxonomy.yaml (промпт-enum, R6). Семантика профилей quick/deep/custom —
  отдельная задача (п. 5.2, сейчас имя без различий выборки).
- Открытое: Kimi живой прогон — ждёт пополнения баланса (команды в
  снимках ниже).

Снимок от 2026-10-25 ~15:10 UTC (сессия S8-7 — управление источниками и
расписаниями из UI; HEAD `25b9b43` = origin/main):

- **S8-7 запушен и ПРОВЕРЕН НА СТЕНДЕ** (`8e63797` + фикс `2a38eda`):
  страница /sources (только admin, RBAC manage) — добавление/правка/
  удаление источников БД и расписаний пересканов (cron, scan_window) из
  UI. Правка идёт в connections.yaml через yaml.v3 Node (комментарии и
  ${ENV} сохраняются), применение горячее без рестарта (atomic swap +
  scheduler.ReplaceSources); пароль в dsn/uri — только ${ENV} (п. 12,
  fail-closed); кнопка «Проверить» пингует реальное подключение. Живой
  прогон: добавление+расписание → scheduler перестроился без рестарта,
  удаление → снято, «Проверить: OK», открытый пароль отклонён. На .113
  работает сборка 2a38eda.
- Открытое: Kimi живой прогон — по-прежнему ждёт пополнения баланса
  (ключ на стенде; команды в HANDOFF ниже).

Снимок от 2026-10-25 ~14:00 UTC (сессия S8-5/S8-6 — Kimi-интеграция +
CSRF-фикс + евиденс вердиктов; HEAD `fd2c4fa` = origin/main):

- **S8-6 (CSRF-фикс + евиденс) запушен и ПРОВЕРЕН НА СТЕНДЕ** (`76b0d5a`):
  баг «CSRF-токен отсутствует» при запуске скана из UI (классическая форма
  без заголовка) — middleware принимает токен hidden-полем csrf_token;
  живой прогон: форма 302 → скан запущен. Евиденс вердиктов: sample.examples
  (≤3 маскированных, ADR-0010), evidence.llm/llm_verify (reason_ru, агент,
  модель); /verdicts — колонка «Евиденс» с раскрытием, live-HTML содержит
  примеры и rules/* matched/total. На .113 работает сборка 76b0d5a.
- **S8-5 (Kimi) — интеграция готова, живой прогон ЗАБЛОКИРОВАН балансом**
  (`4d7b222`): реестр агентов → api.moonshot.ai/v1/chat/completions,
  model kimi-k2.6, api_key_env KIMI_API_KEY, allowlist [api.moonshot.ai];
  ci.env обновлён. Ключ пользователя записан на стенде (/opt/zond/zond.env,
  mode 600), но аккаунт suspended (insufficient balance) — ждёт пополнения
  platform.kimi.com. Конформанс пути проверен fake-LLM: eval 1000 колонок —
  78 обращений (24 классификации, 54 small_sample by design), токены и $
  учтены. После пополнения: `zond scan -source ch-test -llm` на .113 и
  `go run ./cmd/eval run -llm -price-in 3 -price-out 15`.
- Прошлые снимки (проверка S8-2/8-3/8-4 и S8-4 fuzz) удалены 2026-11-01 —
  относились к выведенному стенду .113/.119; ключевые открытые вопросы
  перенесены в актуальный снимок.


## 7. ЧЕК-ЛИСТ ПЕРЕДАЧИ (выполняет каждый агент)

- [ ] `make ci` зелёный (или зафиксировано, что красное — и почему).
- [ ] Все сделанные коммиты соответствуют разделу 4.
- [ ] Раздел 6 переписан фактическим состоянием: закоммичено / в работе /
      следующий шаг / проблемы / вопросы. Устаревший снимок удалён.
- [ ] В разделе 6 указана дата/время снимка.
- [ ] Следующему агенту передан ВЕСЬ файл целиком, как есть.
