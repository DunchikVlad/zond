# Прогресс: этап 7, инкремент 7б — backup/restore (п. 15.2) + backup_failed

Дата: 2026-10-22
Исполнитель: агент сессии (этап 7 — «Харденинг и релиз v0.1»)
Статус: **done** (S7б). Следующие: S7в — Vault (ADR-0012); S7г — релиз v0.1
(security-чеклист п. 14, подпись/checksums/SBOM, документация эксплуатации,
smoke-чек, тег).

## 1. Цель

Blueprint п. 15.2: онлайн-копия Verdict Store через `VACUUM INTO` без
остановки сервиса (`zond backup --out`), расписание через cron инстанса,
RPO ≤24 ч, учебное восстановление (DoD п. 22); п. 17 — алерт
`backup_failed`. Копии хранятся вне инстанса (S3/WORM) — ответственность
оператора.

## 2. Что сделано

| Чанк | Результат |
|---|---|
| S7б-1 | `store.Backup(ctx, outPath)` — VACUUM INTO: согласованный снимок на работающем инстансе; fail-closed против перезаписи существующего файла; права 0600 на копии; `store.BackupFilename` (zond-ГГГГММДД-ЧЧММСС.db). `connections.yaml`: секция `backup {schedule, dir}` (строгая схема; `dir` обязателен при schedule). CLI `zond backup -out <path>`: копия + аудит-запись `backup` (actor cli, категория admin, details status ok/fail с размером/ошибкой), код 1 при неудаче |
| S7б-2 | CLI `zond restore -from <копия> -to <пустой каталог>`: перенос копии как zond.db, открытие (goose up = migrate), пересчёт hash-chain — автоматизация учебного восстановления (DoD п. 22); fail-closed на непустой каталог. `scheduler.WithBackup(schedule, dir)`: периодическая копия по cron из конфигурации; каждая попытка (ok/fail) — в аудит (actor scheduler). `store.LatestBackupEvents` — парсинг аудит-записей backup. Правило алертинга `backup_failed` (п. 17): стреляет при неудаче последней попытки; при заданном расписании и отсутствии успешной копии свежее 24 ч (RPO) — тоже; авто-закрытие после успешной копии; цель `verdict_store`. serve: wiring расписания и backupExpected в evaluator |

## 3. Ключевые решения

См. `docs/decisions/ADR-impl-stage-7b-backup.md`. Кратко:

- **События бэкапа — в audit-лог** (а не отдельная таблица): п. 14.2 уже
  требует журналировать фоновые задачи; hash-chain даёт неотказуемость;
  правило читает готовый поток.
- **Неудача копии — тоже аудит-запись** (status=fail): иначе правило не
  отличит «не делали» от «не получилось».
- **VACUUM INTO + запрет перезаписи + 0600** — fail-closed по п. 14.

## 4. Проверки (протокол — docs/validation/2026-10-22-stage-7b.md)

- `go build`, `go vet`, `gofmt` — чисто; `golangci-lint` — 0 issues.
- `go test ./...` — все пакеты ok; race затронутых — ok.
- `make ci`, `make config-check` — зелёные.
- Smoke: `zond backup` (копия 147456 байт, audit verify копии OK,
  перезапись → exit 1); `zond restore` (OK, непустой каталог → exit 1).

## 5. Изменённые файлы

Новые: `internal/verdict/store/backup.go`, `backup_test.go`.
Изменённые: `internal/config/config.go` (+backup-секция, валидация, тест),
`cmd/zond/main.go` (backup/restore/usage/wiring), `internal/scheduler/
scheduler.go` (+WithBackup, задача backup, тесты), `internal/observe/
alerts.go` (+правило backup_failed, тесты).
architecture.md — в «-док» коммите.

## 6. Не вошло (следующие инкременты этапа 7)

- **S7в** — Vault на демо-контуре (ADR-0012): проверка `vault` в doctor
  станет реальной; секреты резолвятся из Vault.
- **S7г** — релиз v0.1: security-чеклист (п. 14), подпись/checksums/SBOM
  (syft/cosign — артефакты релиза), документация эксплуатации, smoke-чек,
  тег v0.1.
- Отдельно: `make bench` (п. 16.8), прогон `cmd/eval run -llm` при
  появлении LLM-стенда.
