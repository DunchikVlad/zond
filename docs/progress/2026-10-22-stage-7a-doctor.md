# Прогресс: этап 7, инкремент 7а — preflight doctor (п. 15.3)

Дата: 2026-10-22
Исполнитель: агент сессии (этап 7 — «Харденинг и релиз v0.1»)
Статус: **done** (S7а). Следующие: S7б — backup/restore (п. 15.2) +
правило `backup_failed` (п. 17); S7в — Vault (ADR-0012); S7г — релиз v0.1
(подпись, SBOM, чеклист, тег).

## 1. Цель

Blueprint п. 15.3: проверки перед вводом в эксплуатацию — свободное место
на томе SQLite (≥2× размера БД), доступность источников (Ping + probe
readonly), доступность и формат ответа агентов, TLS-сертификаты, наличие
обязательных env; выход — таблица OK/FAIL с кодами; FAIL блокирует старт
`serve` при флаге `--strict`.

## 2. Что сделано

| Чанк | Результат |
|---|---|
| S7а-1 | Пакет `internal/doctor`: `Report`/`Result` (статусы OK/FAIL/WARN/SKIP, стабильные коды `disk.space`, `audit.chain`, `source.open/ping`, `agent.env/egress/dns/probe`, `tls.cert`, `vault`), `Text`-таблица со сводкой, `HasFail` |
| S7а-2 | Проверки: `disk.space` — свободное место на томе БД ≥ 2× размера файла (POSIX — `syscall.Statfs`; Windows — `GetDiskFreeSpaceExW` через `x/sys/windows`, build-tags; x/sys стала прямой зависимостью); `store.open` + `audit.chain` — открытие SQLite (goose up) и пересчёт hash-chain (п. 14.2, runbook audit-hash-chain-broken.md); `source.open/ping` — Lookup коннектора + Ping с таймаутом 10с (online); `agent.env` — наличие ключа `api_key_env`; `agent.egress` — конструктор прокси валидирует endpoint по egress-политике (fail-closed DNS, п. 10.7, прецедент agent-check); `agent.dns` — резолв hostname endpoint'а (online); `agent.probe` — пробный `Classify` двух тестовых значений с валидацией формата ответа (п. 5.3, online); `tls.cert` — сертификат SP SSO: читается, парсится (PEM/DER), не истёк на момент проверки; `vault` — SKIP (ADR-0012 — S7в) |
| S7а-3 | CLI `zond doctor [-config configs] [-db zond.db] [-online]`: конфиг не загружается — отчёт всё равно строится (FAIL config.load + независимые проверки), код выхода 1 при любом FAIL; `serve -strict`: preflight (online) до биндинга порта, FAIL — старт отменён с таблицей в stderr |
| S7а-4 | Тесты (6): offline-прогон по сидированному store (диск/цепочка OK, source.open FAIL на незарегистрированном типе, agent.env OK/FAIL по env, egress только у агента с ключом, probe/tls/vault SKIP); nil-конфиг; online-прогон — DNS localhost-короткое замыкание + пробный вызов против httptest-стенда OpenAI-ответа, у агента с `.invalid`-хостом DNS FAIL без сетевого таймаута; разбор endpoint'а в checkDNS; TLS — самоподписанный валидный/истёкший/отсутствующий; отчёт/коды |

## 3. Ключевые решения

См. `docs/decisions/ADR-impl-stage-7a-doctor.md`. Кратко:

- **Один пакет, таблица кодов, два режима (online/offline)** — doctor
  пригоден и в CI (offline: конфиг/env/egress/диск/цепочка), и перед
  вводом (online: ping/probe/DNS).
- **Egress-валидация прокси в offline-режиме** (как agent-check): фейковый
  endpoint = FAIL — fail-closed п. 10.7.
- **Windows-диск через x/sys** (build-tags): POSIX — stdlib Statfs.

## 4. Проверки (протокол — docs/validation/2026-10-22-stage-7a.md)

- `go build`, `go vet`, `gofmt` — чисто; `golangci-lint` — 0 issues.
- `go test ./...` — все пакеты ok; `go test -race ./internal/doctor/` — ok.
- `make ci`, `make config-check` — зелёные.
- Кросс-сборка: `GOOS=linux GOARCH=amd64 go build ./...` и windows —
  ок (build-tags disk-файлов).
- Smoke CLI: `zond doctor` на ci.env — таблица (egress FAIL на
  `api.example` — fail-closed по DNS), код выхода 1; `-online` — probes
  к фейковым endpoint'ам дают FAIL (ожидаемо); битый `-config` — FAIL
  config.load, независимые проверки отработали.

## 5. Изменённые файлы

Новые: `internal/doctor/{doctor.go,doctor_disk_unix.go,doctor_disk_windows.go,doctor_net.go,doctor_test.go}`.
Изменённые: `cmd/zond/main.go` (doctor + serve -strict + usage),
`go.mod`/`go.sum` (golang.org/x/sys — прямая зависимость).
architecture.md — в «-док» коммите.

## 6. Не вошло (следующие инкременты этапа 7)

- **S7б** — backup/restore (п. 15.2): `zond backup --out` (VACUUM INTO),
  учебное восстановление (DoD п. 22), правило `backup_failed` (п. 17).
- **S7в** — Vault на демо-контуре (ADR-0012); проверка `vault` в doctor
  станет реальной.
- **S7г** — релиз v0.1: security-чеклист (п. 14), подпись/checksums/SBOM,
  документация эксплуатации, тег.
