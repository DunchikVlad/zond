# Анализ разрыва и план чанков реализации (gap analysis)

Дата: 2026-10-18
Статус: **реализовано** (этап 0 закрыт 2026-10-18, см. `docs/progress/2026-10-18-stage-0.md`)
Связанные документы:
- `docs/progress/2026-10-18-stage-0.md` (этап 0, статус `planned`)
- `docs/decisions/ADR-impl-stage-0-scaffold.md` (accepted: минимальный scaffold → вертикальный срез)
- Основание: `blueprint.md` п. 3–5, 15–16, 21–22; `architecture.md` п. 7, 12, 13

## 1. Цель

Зафиксировать фактическое состояние проекта, определить полный перечень
отсутствующих артефактов и разбить ближайший объём работ (этап 0) на малые
проверяемые чанки, каждый с результатом, проверками и документированием.

## 2. Что есть (подтверждено инвентаризацией 2026-10-18)

Инвентаризация рабочей директории: **9 markdown-файлов, 0 файлов кода, 0 конфигов, репозиторий git не инициализирован**.

| Артефакт | Состояние |
|---|---|
| `blueprint.md` (v2, APPROVED FOR DEVELOPMENT) | есть, полный |
| `architecture.md` (v1, READY FOR IMPLEMENTATION) | есть, полный |
| `docs/README.md` (правила ведения документации, naming convention) | есть |
| `docs/progress/2026-10-18-stage-0.md` | есть, статус `planned` |
| `docs/validation/2026-10-18-stage-0.md` | есть, подготовительная |
| `docs/security/2026-10-18-stage-0.md` | есть |
| `docs/decisions/ADR-impl-stage-0-scaffold.md` | есть, accepted |
| `docs/runbooks/` (4 шт.: scan-stuck, llm-unavailable, restore, hash-chain) | есть |

Вывод: проектная и организационная база полностью готова, кодовой базы нет.

## 3. Чего нет (подлежит реализации)

### 3.1 Код и структура (blueprint п. 4, architecture п. 3, п. 7)

| Артефакт | Статус | Основание |
|---|---|---|
| git-репозиторий | отсутствует | smoke-сценарий п. 24 начинается с `git clone` |
| Go-модуль (`go.mod`) | отсутствует | п. 3 blueprint |
| `cmd/classifier/` (main + подкоманды) | отсутствует | п. 4 blueprint |
| `internal/config` | отсутствует | п. 4, ADR-0009 |
| `internal/connector/` (contract, registry, clickhouse, mongodb, conftest) | отсутствует | п. 5.1, п. 4 |
| `internal/sampler` | отсутствует | п. 5.2 |
| `internal/analyze/` (meta, rules, cluster) | отсутствует | п. 7, ADR-0002 |
| `internal/fingerprint` | отсутствует | п. 7.6 |
| `internal/agentproxy/` (mask, cache, registry, prompts) | отсутствует | п. 10, ADR-0005/0010 |
| `internal/ensemble` | отсутствует | п. 7 |
| `internal/verdict/` (model, store, drift) | отсутствует | п. 5.4, п. 11.1 |
| `internal/scanengine` | отсутствует | architecture п. 3, п. 13 blueprint |
| `internal/auth`, `internal/api`, `internal/web` | отсутствуют | п. 11, ADR-0007/0011 |
| `internal/audit`, `internal/logging`, `internal/observe` | отсутствуют | ADR-0013 |
| `internal/secrets`, `internal/scheduler` | отсутствуют | ADR-0012, п. 15 |
| `configs/` (connections, detectors, taxonomy) | отсутствуют | п. 12, ADR-0004 |
| `Makefile`, `.golangci.yml`, CI workflow | отсутствуют | п. 16.7, DoD п. 22 |
| `migrations/`, `deploy/docker-compose.yml` | отсутствуют | п. 11.1, п. 15 |
| `cmd/seed`, `evals/` | отсутствуют | п. 16.6, п. 21 |

### 3.2 Среда и инструменты (блокеры)

| Компонент | Состояние | Влияние |
|---|---|---|
| Git | установлен (2.54.0) | ок |
| **Go toolchain** | **не установлен** | блокирует весь этап 0 начиная с `go mod init` |
| **Docker** | **не установлен** | не блокирует этап 0 (юнит-тесты); блокирует testcontainers/conftest (этап 2) и `make smoke` |
| GitHub remote / CI runner | нет | CI-ворота п. 16.7 можно положить как workflow-файл, зелёным он станет после пуша |

## 4. Открытые вопросы (не блокируют scaffold)

1. Module path: blueprint п. 3 — `github.com/<org>/classifier`; до решения использовать
   placeholder (`classifier` как module path), переименование механическое.
2. Организационные решения п. 19.1 blueprint (владелец таксономии, релизная политика,
   SLO-поддержка) — требуются до релиза v0.1, не до этапа 0.
3. Улучшения из architecture п. 11.1 (SLO, роль reviewer, policy long-running scans,
   provenance first-class) — закрываются постепенно, часть уже покрыта blueprint доп. 5.

## 5. Чанк-план этапа 0 (маленькие чанки)

Каждый чанк: результат → проверка → обновление docs. DoD этапа — blueprint п. 21
(этап 0) и п. 22: работающий `classifier version`, валидируемый конфиг, зелёные
`build/test/lint`.

| # | Чанк | Состав | Проверка | Документирование |
|---|---|---|---|---|
| S0-0 | Предусловие: Go toolchain | Установка Go 1.24+ (scoop или офиц. дистрибутив), `go version` | версия ≥1.23 обязана, цель 1.24 | запись в validation |
| S0-1 | Git-репозиторий | `git init`, `.gitignore` (бинарник, `*.db`, `.env`), первый коммит | `git status` чистый; история есть | progress |
| S0-2 | Go-модуль и скелет пакетов | `go mod init`, дерево каталогов п. 4 blueprint, `doc.go`-заглушки, `go build ./...` | сборка зелёная | progress + decisions (module path placeholder) |
| S0-3 | Доменные контракты | `internal/verdict/model.go` (п. 5.4/5.5), `internal/connector/contract.go` + `registry.go` (п. 5.1) | компиляция; юнит-тест реестра (регистрация/дубль/lookup) | progress |
| S0-4 | Конфигурация | `internal/config`: 3 YAML, `${ENV}`-интерполяция, fail-fast со списком ошибок; примеры `configs/*.yaml` без секретов | табличные тесты: валидный / битый / отсутствующий env | progress + security note (примеры без секретов) |
| S0-5 | CLI | `cmd/classifier/main.go` + подкоманда `version` | `go run ./cmd/classifier version` | progress |
| S0-6 | Makefile и lint | Makefile (`build/test/lint/cover`), `.golangci.yml` (заготовка depguard-правил слоёв) | `make build`, `make test`; lint — если бинарник доступен | progress + validation |
| S0-7 | Логирование scaffold | `internal/logging`: JSON-logger, correlation id; интерфейс redact (реализация — позже) | тест формата JSON-строки | progress + security note (уровни, запрет debug у data-пакетов) |
| S0-8 | Закрытие этапа 0 | прогон всех проверок, обновление `progress/2026-10-18-stage-0.md` → done, validation с реальными командами | чеклист DoD этапа 0 | progress + validation |

Чего в этап 0 сознательно **не входит** (фиксируется в progress этапа): коннекторы,
agentproxy, store, API/UI, SSO, audit, Vault — по ADR-impl-stage-0-scaffold.

## 6. Что реализовано в этом шаге

- Проведена полная инвентаризация проекта (файлы, среда, инструменты).
- Составлен исчерпывающий список отсутствующих артефактов с привязкой к blueprint/architecture.
- Этап 0 разбит на 9 малых чанков (S0-0…S0-8) с проверками и документированием.
- Код в этом шаге не писался — только анализ и планирование.

Изменённые/созданные файлы:
- `docs/progress/2026-10-18-gap-analysis.md` (этот документ)

## 7. К чему вернуться позже (вне ближайших чанков)

1. **Этап 1 — вертикальный срез** (CH-коннектор → sampler → meta/rules email+phone+INN+Luhn → SQLite → консольный отчёт).
2. **Этап 2 — MongoDB + conftest** (требует Docker: testcontainers).
3. **Этапы 3–7**: полный regex-слой + кластеризация; Agent Proxy + ensemble; Store+API+UI+SSO+аудит; evals + наблюдаемость; харденинг + Vault + backup + doctor + релиз v0.1.
4. **Инфраструктура**: установка Docker; GitHub remote + включение CI workflow; module path под реальный org.
5. **Организационные решения** blueprint п. 19.1 и архитектурные улучшения architecture п. 11.1 — до релиза v0.1.
6. Расширение runbook-пакета (SSO, Vault, doctor) — blueprint п. 22.1, docs/README п. 10.

## 8. Проверки (как выполнялась инвентаризация)

- Полный перечень файлов рабочей директории: 9 `.md`, файлов кода и конфигов нет.
- `go version` → not found; `docker --version` → not found; `git --version` → 2.54.0.
- Наличие `.git`: отсутствует.
- Сверка состава docs с docs/README п. 8: совпадает.

## 9. Следующие шаги

1. Решить вопрос установки Go (S0-0) — системное действие, требует подтверждения.
2. Выполнить S0-1…S0-8 по чанкам, документируя каждый.
3. Закрыть этап 0, перейти к вертикальному срезу этапа 1.
