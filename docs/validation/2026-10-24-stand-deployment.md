# Валидация: развёртывание свежей версии на тестовом стенде (2026-10-24)

Дата: 2026-10-24
Объект: свежая сборка `main` (`c3a1350`, zond c3a1350-stand) на
`192.168.31.113`, БД-источники на `192.168.31.119`; см.
`docs/progress/2026-10-18-test-environment.md` (дополнение 2026-10-24).

## 1. Что развёрнуто

| Компонент | Хост | Состояние |
|---|---|---|
| zond (linux/amd64, CGO off, modernc-sqlite) | 192.168.31.113 | `/opt/zond/{bin,configs,data,zond.env}`, systemd `zond.service` (enabled, active), `serve -addr 0.0.0.0:8080` |
| ClickHouse 24.8.14.39 | 192.168.31.119 | apt-репо `repo.clickhouse.com/deb stable main` (layout `deb/stable` из старых инструкций отдаёт 404), listen 0.0.0.0:9000/8123, пользователь `test`/`test` (GRANT SELECT на default.* — read-only по п. 12), сид `default.customers` (8 строк, синтетика из deploy/seed) |
| MongoDB 4.4.29 | 192.168.31.119 | tarball в `/opt/mongodb` (пакета mongodb в Ubuntu 26.04 нет), unit `/etc/systemd/system/mongod.service` (Type=simple, LD_LIBRARY_PATH=/opt/mongo-libs — libssl1.1 из security-пула Ubuntu), authorization enabled, listen 0.0.0.0:27017, `test`/`test` (read на testdb), `admin`/`test` (обслуживание), сид `testdb.customers` (8 документов) |

Ограничения стенда (важно для воспроизводимости): ОС Ubuntu 26.04, docker
отсутствует; CPU i7-6700 **без флагов AVX** → ClickHouse 26.x SIGILL
(status=4/ILL) пришлось откатить на 24.8 LTS, MongoDB ≥5.0 не работает
вообще → последняя совместимая 4.4.29 (с libssl1.1).

## 2. Протокол проверок

| Проверка | Команда (на .113, env из /opt/zond/zond.env) | Результат |
|---|---|---|
| Конфигурация | `zond config validate` | OK (sources=4 agents=2 labels=19 taxonomy=1.0.0) |
| Preflight | `zond doctor -config /opt/zond/configs -online` | ch-test OK (ping+подключение), mongo-test OK; FAIL только ожидаемые: ch-prod/mongo-prod (заглушки), agent.egress zond-main/zond-strong (api.example не резолвится, fail-closed п. 10.7) |
| Скан ClickHouse | `zond scan -source ch-test -profile quick` | done за 117 мс, 1/1 таблиц, вердиктов 5: EMAIL 1, PHONE 1, PERSON_NAME 1, UNKNOWN 2 (pending 2) |
| Скан MongoDB | `zond scan -source mongo-test -profile quick` | done за 72 мс, 1/1 коллекций, вердиктов 4: EMAIL 1, PHONE 1, PERSON_NAME 1, UNKNOWN 1 (pending 1) |
| API сканов | `GET /api/v1/scans` (X-Admin-Token) | 200, оба скана со статистикой по лейблам/слоям |
| API вердиктов | `GET /api/v1/verdicts` | 200, вердикты с evidence (маскированный сэмпл, версии taxonomy/detectors), review_status=pending |
| UI | `GET /scans`, `/api/health` | 200 / 200 {"status":"ok"} |
| Ревью-контур (запись) | `POST /api/v1/verdicts/{id}/review {"action":"confirm"}` | 200, review_status → confirmed, pending 3→2; запись review_events + аудит одной транзакцией (п. 13/14.2) |

## 3. Вывод

Свежая версия развёрнута и работает на стенде end-to-end: два источника
реальных БД (CH + Mongo через read-only учётки) сканируются до вердиктов,
вердикты видны через API и UI, ревью-контур пишет корректно. LLM-слой не
проверялся (стенда LLM нет; egress fail-closed подтверждён doctor'ом).

Известные следы для эксплуатации стенда: admin-токен — в
`/opt/zond/zond.env` (CLASSIFIER_ADMIN_TOKEN, mode 600); UI —
http://192.168.31.113:8080. Пароли стенда test/test — осознанно слабые,
только для изолированного контура (п. 4 test-environment).
