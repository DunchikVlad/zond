# Прогресс: этап 5, инкремент 5г — веб-UI (п. 11.3) + scheduler

Дата: 2026-10-20
Исполнитель: Coordinator / Stage 5 (инкремент г — UI и планировщик)
Статус: **done** — этап 5 закрыт (5а аудит, 5б REST API, 5в SSO/токены/RBAC, 5г UI/scheduler)

## 1. Цель

Веб-интерфейс разбора результатов (blueprint п. 11.3, ADR-0007:
server-rendered `html/template` + HTMX vendored, embed.FS) и встроенный
планировщик (п. 15, п. 15.4). Это завершает этап 5: дальше этап 6
(eval-harness) и этап 7 (харденинг).

## 2. Что сделано

| Чанк | Результат |
|---|---|
| 5г-1 | Пакет `internal/web`: `Server` поверх того же слоя store, что REST API (один контракт данных, ADR-impl-5г); middleware CSP `default-src 'self'`/nosniff/no-referrer (п. 14), auth (SSO-cookie → нет сессии: GET → 302 `/saml/login`, POST → 403; dev-режим открыт), RBAC на POST-действиях (п. 11.3); шаблоны embed.FS, статика embed (HTMX 1.9.12 vendored, style.css) |
| 5г-2 | Страницы: `/scans` (список, бейджи статусов включая budget_exceeded/interrupted, прогресс done/total, форма старта, стоп через HTMX), `/scans/{id}` (чекпоинты таблиц, сводка по слоям/лейблам, экономика), `/verdicts` (фильтры scan_id/table/label/sensitivity/review_status/min_conf/cluster_id, risk_first, пагинация, HTMX-фильтр), `/review` (очередь pending risk_first, карточки с evidence-lines whitelist-рендером, reason, confirm/reject/relabel, bulk-выбор, HTMX-своп очереди, конфликты ревью — сообщение в карточке), `/drift` (added/removed/changed), `/cost` (разрез по агентам, доля без LLM), `/audit` (фильтры actor/category/since/scan, индикатор целостности hash-chain, admin-only), `/settings` (read-only: источники без DSN, агенты, пороги, таксономия) |
| 5г-3 | Scheduler (`internal/scheduler`, robfig/cron/v3 — зависимость из п. 3 blueprint): ежедневно 03:17 прочистка `verdict_cache` (`CachePurgeExpired`, аудит `scheduler/cache_purge`); 04:23 retention — `store.PurgeScansOlderThan` (90 дней, одна транзакция: agent_calls/review_events → verdicts → scan_tables → scans, аудит `scheduler/retention_purge`); пересканы по `schedule` источника (config.Source.Schedule, actor "scheduler"); невалидное cron-выражение — warn + аудит, старт не падает |
| 5г-4 | Wiring serve: корневой mux — `/api/` и `/saml/` у API-сервера, всё остальное у web (`/static/` отдаёт embed); флаг `-scheduler` (default true), `defer sched.Stop()`; depguard допускает net/http в internal/web (UI не вызывает LLM) |
| 5г-5 | Тесты: web (рендер всех страниц 200 + ключевой контент, CSP, индекс-редирект, evidence-whitelist — строка «SEKRET» не попала в HTML, анон → 302 /saml/login, viewer GET 200/POST 403, admin старт через fake runner, confirm/конфликт/bulk ревью, actor `sso:` в ReviewedBy); scheduler (purge cache, retention удаляет старое/щадит свежее + аудит, невалидный schedule не роняет старт) |

## 3. Ключевые решения

См. `docs/decisions/ADR-impl-stage-5g-web-ui.md`. Кратко:

- **UI поверх того же слоя store, что REST** — не HTTP-вызовы в свой же API.
  Один контракт данных и дедупликация; транспортный вариант (UI ходит в API
  по loopback) отклонён как лишний хоп без выигрыша в single-instance.
- **Evidence-рендер whitelist'ом** — только известные ключи (rules/sample/
  llm_cache/reason/budget/cluster); неизвестные ключи в HTML не попадают
  (защита от случайной утечки, дополняет ADR-0010).
- **Retention аудита не автоматизирован** — audit_log append-only; автоудаление
  противоречило бы hash-chain. П. 15.4 закрыт архивной процедурой (runbook),
  автоматизируется только со внешним sink/WORM (этап 7).
- **Bulk-ревью — последовательные ApplyReview**, сводка в ответе; частичный
  отказ не откатывает применённые (идемпотентность ApplyReview это допускает).
- **Клавиатурные shortcuts отложены** — CSP default-src 'self' без
  'unsafe-inline' запрещает inline-скрипты; отдельный JS-файл — в доработку
  после CSP-политики для скриптов страницы ревью.

## 4. Проверки (протокол — docs/validation/2026-10-20-stage-5g.md)

- `go build`, `go vet`, `gofmt` — чисто; `golangci-lint` — 0 issues.
- `go test ./...`, `go test -race ./internal/...` — все пакеты ok.
- `make config-check` — OK.
- Smoke serve: `/scans` 200, `/static/htmx.min.js` 200, `/api/health` 200,
  планировщик запущен (лог).

## 5. Изменённые файлы

Новые: `internal/web/{server.go,server_test.go,templates/*.html,static/style.css,static/htmx.min.js}`,
`internal/scheduler/{scheduler.go,scheduler_test.go}`, `internal/verdict/store/{retention.go,retention_test.go}`.
Изменённые: `cmd/zond/main.go` (корневой mux, scheduler, флаг), `.golangci.yml`,
`internal/config/config.go` (Source.Schedule), `configs/connections.yaml`
(пример schedule). Заглушки `internal/web/doc.go`, `internal/scheduler/doc.go`
удалены. `go.mod` — robfig/cron/v3.

## 6. Не вошло (этапы 6–7 и доработки)

- Этап 6: eval-harness (генератор датасета, F1-отчёты, sweep порогов).
- Этап 7: харденинг — `zond doctor`, Vault (ADR-0012), backup/restore (п. 15.2),
  SIEM-sink аудита, подписанные WORM-снапшоты, rate-limit 100 req/s (п. 11.2),
  hot-reload detectors.yaml (ADR-0014), async-экспорт по ссылке.
- UI-доработки: shortcuts ревью (отдельный JS при ослаблении CSP на страницу),
  окна сканирования `scan_window` (п. 13.2) — в scheduler, графики экономики.
