# Валидация: эталонный smoke-контур на стенде (DoD п. 22) — 2026-10-24

Дата: 2026-10-24
Объект: `make smoke` (blueprint п. 15, DoD п. 22, ADR-impl D7) — первый
реальный прогон; машина — тестовый стенд `192.168.31.113` (Docker
29.1.3, Compose 2.40.3, установлен для прогона). Контур — эталонный
compose (`deploy/docker-compose.yml` + override `deploy/docker-compose.stand.yml`),
не тестовые БД стенда.

## 1. Протокол

| Шаг | Команда | Результат |
|---|---|---|
| Compose-конфиг | `docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.stand.yml config` | OK |
| Разовый скан (DoD) | `... --profile smoke run --rm --build smoke-scan` | код 0: скан `ch-smoke` **done** за 6.832 с, 15/15 таблиц, вердиктов 373 (UNKNOWN 323, PERSON_NAME 48, EMAIL 1, PHONE 1), кластеры 307, LLM-вызовов 0, $0 |
| Вердикты в UI | `up -d app` → `GET :8080/api/health`, `/scans`, `/api/v1/scans`, `/api/v1/verdicts` | health ok; UI /scans 200 со сканом `b597db48`; вердикты отдаются (SSO выключен — smoke-режим без auth, actor api) |
| Очистка | `down -v` (тома удалены) | OK; основной `zond.service` возвращён (active, health ok) |

**Зелёный smoke по DoD: скан дошёл до done с кодом 0, вердикты видны в UI
на 127.0.0.1:8080.** Ранее известный пробел чеклиста п. 14 закрыт.

## 2. Дефекты, найденные первым прогоном (оба исправлены)

1. **`smoke-scan` без `build:`-секции** — `run --build smoke-scan` пытался
   pull несуществующего образа `zond:smoke` (`pull access denied`).
   Исправление: та же `build`-секция, что у `app` (общий кэш слоёв,
   образ один). Никогда не воспроизводилось раньше — контур не прогонялся.
2. **`/data` в scratch-образе принадлежал root** — named volume
   инициализируется владельцем каталога образа, SQLite под UID 65534
   не открылся (`unable to open database file (14)`). Исправление:
   `/data` с владельцем 65534 в Dockerfile (`COPY --chown=65534:65534`).

## 3. Отклонения от эталонного контура (зафиксированы)

- **mongo:7 → mongo:4.4** через `deploy/docker-compose.stand.yml`: CPU
  стенда без AVX, MongoDB ≥5.0 не стартует (SIGILL). Healthcheck переведён
  на легаси-шелл `mongo` (в образе 4.4 нет mongosh). ClickHouse 24.8 и
  scratch-образ zond ограничение не затрагивает.
- Прогон с рабочей машины разработчика вместо `make smoke` локально —
  команды идентичны (те же файлы + override), на хосте нет docker.

## 4. Вывод

ADR-impl D7 выполнен: smoke прогнан зелёным до тега. Предусловие тега
v0.1 соблюдено; релизный pipeline (release.yml) готов к запуску на теге.
