# Валидация: развёртывание на новом стенде Debian 13 (2026-11-01)

Дата: 2026-11-01
Объект: свежая сборка `main` (`d27576b`, zond v0.1-38-gd27576b-dirty-stand,
linux/amd64, CGO off) на `192.168.31.248`; БД-источники на `192.168.31.64`.
Стенд пересобран с нуля (прежний .113/.119 выведен), см.
`docs/progress/2026-10-18-test-environment.md` (дополнение п. 9).

## 1. Что развёрнуто

| Компонент | Хост | Состояние |
|---|---|---|
| zond (linux/amd64, modernc-sqlite) | 192.168.31.248 | `/opt/zond/{bin,configs,data,zond.env}`, systemd `zond.service` (enabled, active), `serve -addr 0.0.0.0:8080 -scheduler` |
| ClickHouse 26.9.9.28 | 192.168.31.64 | deb stable, listen 0.0.0.0:9000/8123, `test`/`test` (профиль zond_readonly, readonly=2, max_execution_time=300, max_memory_usage=10 ГБ), сид `default.customers` (8 строк) |
| MongoDB 8.0.34 | 192.168.31.64 | deb из репозитория bookworm (серверных пакетов для trixie нет; зависимости libssl3/libcurl4 закрыты Provides t64-пакетов trixie), authorization enabled, listen 0.0.0.0:27017, `test`/`test` (read на testdb) + `admin`/`test`, сид `testdb.customers` (8 документов) |
| PostgreSQL 17.11 | 192.168.31.64 | пакет trixie, listen `*` (conf.d/zond.conf), pg_hba: `host testdb test 192.168.31.0/24 scram-sha-256`, `test`/`test` (SELECT на customers), сид `testdb.customers` (8 строк) |

ОС обоих хостов — Debian 13 (trixie), CPU AMD Ryzen 7 7700 (AVX2) —
ограничения старого стенда (CH 24.8 / Mongo 4.4 из-за отсутствия AVX) сняты.
Docker отсутствует, развёртывание нативное. sudo настроен (NOPASSWD, test).

## 2. Протокол проверок

| Проверка | Команда | Результат |
|---|---|---|
| Конфигурация | `zond config validate` | OK (sources=5 agents=2 labels=19 taxonomy=1.0.0) |
| Preflight | `zond doctor -online` | ch-test/mongo-test/pg-test OK; FAIL только ожидаемые: ch-prod/mongo-prod (заглушки), agent.env zond-main/zond-strong (KIMI_API_KEY не задан на новом стенде) |
| Скан ClickHouse | `scan -source ch-test -profile quick` | done, 21 таблица (см. замечание З1), вердиктов 489: EMAIL 1, PHONE 1, PERSON_NAME 64, UNKNOWN 423 (pending 423) |
| Скан MongoDB | `scan -source mongo-test -profile quick/deep` | done за ~50 мс, вердиктов 4: EMAIL 1, PHONE 1, PERSON_NAME 1, UNKNOWN 1 (pending 1) |
| Скан PostgreSQL (S9-5) | `scan -source pg-test -profile quick` | done за 55 мс, вердиктов 5: EMAIL 1, PHONE 1, PERSON_NAME 1, UNKNOWN 2 (pending 2) |
| API сканов/вердиктов | `GET /api/v1/scans`, `/verdicts` | 200, статистика по лейблам/слоям, evidence маскирован (`t***@example.org`) |
| UI | `GET /scans /verdicts /review /drift /cost /audit /sources /settings`, `/api/health` | все 200 |
| Ревью-контур | `POST /api/v1/verdicts/{id}/review {"action":"confirm"}` | 200, review_status → confirmed, reviewed_by=api, reviewed_at проставлен |
| Дрейф | `GET /api/v1/drift?source_id=mongo-test` | 200, quick→deep без расхождений (added/removed/changed пусты) |
| Экспорт | `GET /api/v1/export?scan_id=…&format=csv` | 200, CSV с маскированными примерами |
| Аудит | `zond audit verify` | OK (7 записей, hash-chain сходится) |
| Бэкап | `zond backup -out` | OK (458 752 Б, 6 мс) |
| Resume done-скана | `POST /scans/{id}/resume` | корректный отказ `invalid_request` («только partial/interrupted») |
| Description без LLM | `POST /scans/{id}/description-runs` | корректный отказ `invalid_request` («сервер без description runner») |
| Rate-limit API (S9-6) | burst 500 GET /api/v1/scans за 177 мс (2829 rps) | все 200 — лимитер не срабатывает, причина в замечании З2 |

## 3. Замечания

### З1 (среднее, баг коннектора ClickHouse): сканируются системные view `INFORMATION_SCHEMA`

`internal/connector/clickhouse/connector.go:43` исключает базы
`('system','information_schema')`, но сравнение регистрозависимо, а
ClickHouse 26.x создаёт ДВЕ копии системной БД: `information_schema` и
`INFORMATION_SCHEMA` (по 20 view). Итог скана ch-test: 21 таблица вместо 1,
489 вердиктов вместо ~5: 64 ложных `PERSON_NAME` (PII, auto_accepted, conf
0.85 — словарный матч имён колонок системных view) и 423 `UNKNOWN` в
очереди ревью. На старом стенде (CH 24.8) базы `INFORMATION_SCHEMA` не
было, поэтому дефект не проявлялся. Рекомендация: сравнение через
`lower(database)` (заодно закроет будущие регистровые варианты).

### З2 (важное, безопасность): при `sso.enabled: false` аутентификация отключена полностью

Blueprint п. 12: «`enabled: false` — режим без SSO (**только admin-токен**,
для dev-контура и air-gapped)». Фактически при `sso.enabled: false`:
- API: `withAuth` возвращает обработчик без проверок — `GET /api/v1/scans`
  отдаёт 200 **без токена** и **с неверным токеном**;
- Web: `internal/web/server.go:292` подставляет субъекта `dev`/admin —
  `/settings`, `/sources`, `/audit` и все мутации доступны анонимно;
- побочный эффект: rate-limit субъектов (S9-6) в этом режиме не действует
  (500 запросов за 177 мс — все 200, ни одного 429).

`CLASSIFIER_ADMIN_TOKEN` в этом режиме ни от чего не защищает. Для
изолированного стенда допустимо, но стенд слушает 0.0.0.0:8080 в LAN —
любой в сегменте может запускать сканы и менять конфиги. Прежние протоколы
всегда ходили с токеном, поэтому расхождение не замечали. Рекомендация:
либо требовать admin-токен при `sso.enabled=false` (соответствие п. 12),
либо явно зафиксировать в blueprint/dev-режиме «без аутентификации» и
не выставлять такой инстанс в сеть.

### З3 (низкое, тесты): 3 теста agentproxy падают на Windows

`TestUsageAndLatencyParsed`, `TestUsageAbsentZero`, `TestVerifyUsageLatency`
(`internal/agentproxy/proxy_test.go`): `time.Since(start)` даёт 0 из-за
грубой гранулярности монотонного таймера Windows (fake-LLM отвечает
мгновенно), тесты требуют `Latency > 0`. На Linux те же тесты зелёные
(проверено кросс-сборкой тест-бинарника на стенде, `-count=3` PASS).
`make ci` на Windows-машине из-за этого красный; дефект окружения, не кода.

### З4 (инфраструктура стенда): исходящие загрузки с внешних CDN ~10–15 КБ/с

Большие файлы с packages.clickhouse.com, repo.mongodb.org, deb.debian.org
идут на 10–15 КБ/с; apt-метод https зависает намертво (30+ мин без
прогресса). Обход (применён): скачивание deb на машине разработчика → scp →
`dpkg -i` / подкладка в `/var/cache/apt/archives`. Учитывать при
обновлении ПО стенда; apt update самих индексов работает нормально.

### З5 (устаревший артефакт): `deploy/docker-compose.stand.yml`

Ссылается на старый стенд .113 и образ mongo:4.4 (ограничение AVX
i7-6700). Для нового стенда неприменим (AVX2 есть, Docker отсутствует).
Пометить устаревшим или удалить отдельным решением владельца.

### З6 (ожидаемо): LLM-контур не проверялся

`KIMI_API_KEY` на новый стенд не переносился; doctor корректно фиксирует
`agent.env FAIL` (fail-closed), description-runs без LLM отклоняется с
понятной ошибкой. Живой прогон LLM (S8-5, S9-4) — после появления ключа.

## 4. Вывод

Свежая версия развёрнута на новом стенде end-to-end: три типа БД
(ClickHouse 26.9, MongoDB 8.0, PostgreSQL 17 — впервые живьём, S9-5)
сканируются до вердиктов, API/UI/ревью/дрейф/экспорт/аудит/бэкап работают.
Содержательные замечания: сканирование `INFORMATION_SCHEMA` (З1) и
полностью открытый доступ при выключенном SSO (З2).

Следы для эксплуатации: admin-токен — `/opt/zond/zond.env` (mode 600);
UI — http://192.168.31.248:8080. Пароли стенда test/test — только для
изолированного контура (п. 4 test-environment).

## 5. Дополнение: проверка фиксов S9-8 (З1/З2) на стенде

Дата: 2026-11-01 (вечер). Сборка `v0.1-41-g55d99c0-dirty-stand` на .248.
Инкремент: `docs/progress/2026-11-01-stage-9-8-stand-fixes.md`.

| Проверка | Результат |
|---|---|
| **З1**: повторный скан `ch-test quick` | **1 таблица** (`default.customers`), 5 вердиктов (EMAIL 1, PHONE 1, PERSON_NAME 1, UNKNOWN 2) — системные view INFORMATION_SCHEMA исключены |
| **З2 API**: `GET /api/v1/scans` без токена / с неверным | **401 / 401** (раньше 200) |
| **З2 API**: с верным X-Admin-Token | 200 |
| **З2 UI**: GET /scans, /settings без сессии | **302 → /login** |
| **З2 UI**: GET /login | 200 (форма); POST неверный токен → 403; верный → 302 /scans + cookie `zond_session`; /scans и /settings с сессией → 200 |
| **З2 rate-limit (S9-6)**: burst 500 GET /api/v1/scans (282 rps) | **226 × 429**, 274 × 200 — лимитер действует (раньше все 200) |
| **З2 fail-fast**: `serve` без CLASSIFIER_ADMIN_TOKEN при sso off | выход с кодом 2 и сообщением о п. 12 |
| health без auth | 200 (по построению, п. 15) |
| Аудит | `admin_token_used` (warn) фиксируется; hash-chain OK (523 записи) |
| doctor -online | ch-test/mongo-test/pg-test OK, итог без изменений |

Проверки перед деплоем: `go vet`/build/`go test ./...` локально зелёные;
`go test -race` (api, web, clickhouse) на Linux-стенде (gcc + go1.27.3
в /tmp/gotc, vendor) — зелёные (api 314 с, web 162 с). Замечания З1/З2
закрыты; З3–З6 остаются открытыми (см. п. 3).

## 6. Дополнение 2026-11-03: живой LLM-прогон через локальную Ollama

LLM-контур проверен живьём на стенде через локальную модель (п. 10.7 —
OpenAI-совместимый локальный эндпоинт):

- **Топология**: Ollama 0.40.14 на машине разработчика (192.168.31.141),
  модель `qwen3:30b` (Q4_K_M, 99% GPU). Доступ со стенда — временный
  SSH-туннель `.248:11434 → 127.0.0.1:11434` (запуск с машины разработчика:
  `ssh -N -R 11434:127.0.0.1:11434 test@192.168.31.248`; без туннеля
  agent-check и LLM-сканы не работают). На стенде `detectors.yaml`:
  оба агента (zond-main/zond-strong) → `http://127.0.0.1:11434/v1/chat/completions`,
  model `qwen3:30b`, api_key_env `OLLAMA_API_KEY=dummy` (есть в zond.env),
  timeout 300 с, retries 1, allowlist пуст (loopback разрешён, п. 10.7).
  Исходный конфиг Kimi — бэкап `/tmp/detectors-backup.yaml` на .248.
- **agent-check -online**: оба агента OK (пробный вызов, схема ответа
  валидна).
- **Живой скан** `zond scan -source ch-test -profile custom -llm`: done за
  2м28с, 12 вердиктов, по слоям ensemble=10 llm=2. LLM вызван для колонок
  серой зоны (нейтральное имя + частичный regex-матч): `pole1` classify →
  PHONE (PII), `pole2` classify → EMAIL, верификатор отклонил → FREE_TEXT.
  Каскад classify→verify (эскалация п. 7) отработал на живой модели.
- **Изоляция и маскирование (ADR-0010)** подтверждены в reason_ru модели:
  она видела только маскированные значения (`+7 916 XXXX**`,
  `u***@example.com`), имён БД/таблиц/хостов в запросах нет.
- **Экономика**: токены in/out 1920/5870 (qwen3 «thinking» увеличивает
  out), латентность вызовов 23–52 с (30B на одной GPU), $0 (локальная
  модель; в model_prices цены не заведены).
- Демо-данные .64 дополнены: `default.staff` (200 строк, колонки
  паспорт/карта_лояльности — словарный матч 0.85) и `default.gray_test`
  (200 строк, pole1/pole2 — серая зона для LLM).

### З7 (новое замечание, среднее): `min_rows` профиля сэмпла не применяется

`detectors.yaml` декларирует `min_rows` (п. 5.2: «ниже — берём всё»), но
`scanengine` не передаёт его в `connector.SampleSpec` (в SPI поля MinRows
нет) — процентный сэмпл таблицы из 8 строк дал 1 строку, и LLM-слой
молчал (small_sample: 1 < 3). Обход для живого LLM-теста — наполнение
таблиц сотнями строк. Фикс — отдельным инкрементом: добавить MinRows в
SampleSpec и применять в коннекторах/сэмплере.
