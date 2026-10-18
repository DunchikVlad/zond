# Прогресс: этап 1 — вертикальный срез (ClickHouse → rules → SQLite → отчёт)

Дата: 2026-10-18
Исполнитель: Coordinator / Stage 1
Статус: **done** (код и проверки; интеграция с реальным ClickHouse — в CI, на стенде — после установки БД)

## 1. Цель

End-to-end срез без LLM (blueprint п. 21, этап 1): коннектор ClickHouse →
сэмплер → слои 0–1 (email/phone/ИНН/Luhn) → Verdict Store (SQLite) →
консольный отчёт.

## 2. Выполненные чанки

| Чанк | Результат | Коммит |
|---|---|---|
| S1-0 | Переименование `classifier` → `zond` в blueprint/architecture (Changelog доп. 6), id агентов zond-main/strong | 0006a83 |
| S1-1 | Движок recognizer'ов; email/phone/ИНН(10/12, контрольная сумма ФНС)/Luhn; золотые вектора (стартовые ~20+ на тип) | 6fb2ebb |
| S1-2 | sampler: потоковый пул, дедуп, усечение, null/skipped | ba5570f |
| S1-3 | Слой 0 meta (словари taxonomy + regex имён, confidence 0.85/0.60 по п. 5.6); ensemble-минимум (checksum→0.99; ≥tau_accept→auto; иначе pending) | ba5570f |
| S1-4 | Verdict Store: SQLite modernc (WAL, busy_timeout), миграции goose embed; таблицы scans/scan_tables/verdicts; up→down→up тест | a52e0d3 |
| S1-5 | scanengine: FSM прогона, чекпоинт после таблицы, недоступная таблица не роняет скан (п. 6), small_sample, консольный отчёт; E2E на fake-коннекторе | 9211df7 |
| S1-6 | Коннектор ClickHouse (п. 9): system.columns, unwrap Nullable/LowCardinality/FixedString, rand-сэмпл; интеграционный тест testcontainers (скип без Docker) | de0fb49 |
| S1-7 | CLI `zond scan -source … -db …`; synonyms в taxonomy.yaml | 1ab7fcc |

## 3. Ключевые решения и находки

- **goose: один файл с `-- +goose Up`/`-- +goose Down` вместо пары .up.sql/.down.sql.**
  Коллектор goose v3.24–3.29 собирает `*.sql` и падает с «duplicate version»,
  если up и down лежат отдельными файлами одной версии (воспроизведено
  минимальным примером вне проекта). Подробнее: `docs/decisions/ADR-impl-goose-migrations-format.md`.
- Интерполяция секретов и read-only учётки — как в этапе 0; коннектор получает
  уже разрешённый DSN.
- Sensitivity вердикта — из taxonomy.yaml (маппинг в CLI wiring).
- Расхождения с полным объёмом этапа (отложено): resume (п. 13), conftest
  против двух БД (этап 2), SAMPLE-оптимизация и сэмплинг-ключи CH (п. 9),
  сложные типы CH Array/Tuple/Map (п. 9) сейчас идут в Skipped.

## 4. Проверки (протокол — docs/validation/2026-10-18-stage-1.md)

- `go vet`, `gofmt`, `go build` — зелёные; `golangci-lint` — 0 issues.
- `go test ./...` — все пакеты ok (в т.ч. E2E scanengine: 6 вердиктов,
  checksum 0.99, partial при ошибке таблицы, small_sample при null>0.95,
  отсутствие сырых значений в evidence).
- `go test -race ./internal/...` (cgo/mingw) — зелёный.
- Интеграционный тест ClickHouse — SKIP локально (нет Docker), прогон в CI.
- CLI: `zond scan -source ch-test` дошёл до сетевого подключения стенда
  (192.168.31.119:9000 — connection refused: ClickHouse на стенде пока не
  установлен, см. следующие шаги).

## 5. Изменённые файлы

`internal/analyze/rules/*`, `internal/analyze/meta/*`, `internal/sampler/*`,
`internal/ensemble/*`, `internal/verdict/store/*` (+migrations),
`internal/scanengine/*`, `internal/connector/clickhouse/*`, `cmd/zond`,
`internal/config` (synonyms), `configs/taxonomy.yaml`, `configs/detectors.yaml`,
`blueprint.md`, `architecture.md`, `go.mod`, `go.sum`.

## 6. Следующие шаги

1. Установить ClickHouse (+позже MongoDB) на тестовый стенд (192.168.31.119):
   нужен SSH-доступ (см. docs/progress/2026-10-18-test-environment.md);
   вариант: plink/scoop для неинтерактивного входа или установка вручную.
2. Прогнать `zond scan -source ch-test` против живого CH — первые реальные
   вердикты (точка раннего сигнала blueprint п. 21).
3. Этап 2: MongoDB-коннектор (flatten, полиморфизм, п. 8) + conftest против обеих БД.
