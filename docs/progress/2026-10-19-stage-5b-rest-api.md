# Прогресс: этап 5, инкремент 5б — REST API v1 (blueprint п. 11.2)

Дата: 2026-10-19
Исполнитель: Coordinator / Stage 5 (инкремент б — REST API)
Статус: **done**

## 1. Цель

Поднять REST API v1 (blueprint п. 11.2) поверх Verdict Store: список и
карточки сканов, асинхронный старт/мягкая остановка, фильтрованные вердикты
с сортировкой risk_first, ручное ревью с append-only журналом, дрейф между
прогонами, экономика LLM-вызовов, экспорт CSV/JSON, health/ready. Это
фундамент веб-UI (5г) и SSO-интеграции (5в): все мутации и экспорт уже
аудируются (п. 14.2), каждый запрос получает correlation id (п. 14.1).

## 2. Что сделано

| Чанк | Результат |
|---|---|
| 5б-1 | Миграция `0005_review_events.sql`: `review_events(id, verdict_id FK, action, from_label, to_label, actor, ts)` + индекс по verdict_id + append-only триггеры (паттерн audit_log 0004; тело в `+goose StatementBegin/End`) |
| 5б-2 | Store-чтения: `ListScans` (фильтры status/source, пагинация с total, свежие первыми), `GetScan` (ErrNoRows → 404), `ScanTables` (прогресс по чекпоинтам п. 13), `ListVerdictsFiltered` (scan_id/label/sensitivity/min_conf/review_status/table LIKE/cluster_id, сортировка `risk_first` = PCI/PII/PHI × confidence desc), `GetVerdict`, `VerdictsForExport` (лимит export_max_rows), `Ping` (readiness) |
| 5б-3 | `ApplyReview` — атомарная смена review_status + review_events + аудит одной транзакцией (п. 13/14.2); конфликты (повторный статус, relabel на тот же лейбл/без лейбла, неизвестное действие) — типизированный `ReviewConflict` без какой-либо записи; `ListReviewEvents` для карточки вердикта |
| 5б-4 | Пакет `internal/verdict/drift`: `Compare` (новые/исчезнувшие колонки, смены лейблов/уверенности; эффективный лейбл = final_label приоритетнее; порог шума Δconf ≥ 0.05), `BetweenLatest` (два последних не-running прогона источника, since-ограничение) |
| 5б-5 | Пакет `internal/api`: сервер на stdlib `http.ServeMux` (Go 1.22+ patterns), middleware correlation id (`X-Request-ID` принять/сгенерировать, ctx → access-лог), единый конверт ошибок `{error:{code,message,details}}`, коды п. 11.2 + `verdict_not_found` (ADR D7); обработчики всех маршрутов п. 11.2; экспорт CSV/JSON с лимитом (409 + async-намёк) и аудитом до выдачи (fail-closed) |
| 5б-6 | Движок: `ScanWithID` (scan_id выдаётся до завершения, Scan делегирует), мягкая остановка — ctx-отмена между таблицами → статус `interrupted`, финализация через `context.WithoutCancel` (прогон не «вечный» running) |
| 5б-7 | CLI `zond serve`: `-addr` (default 127.0.0.1:8080 — до SSO только loopback, ADR D1), `-export-max-rows`, `-llm`; `engineRunner` (api.ScanRunner): Ping источника до старта (502 source_unavailable синхронно), 1 активный прогон на источник (п. 13.2), реестр cancel-функций для stop; graceful shutdown (SIGINT/SIGTERM, 5с) |
| 5б-8 | `.golangci.yml`: depguard `llm-only-via-agentproxy` допускает net/http в `internal/api/**` и `cmd/**` (предусмотрено комментарием этапа 0; изоляция LLM не ослабла — ADR D10) |
| 5б-9 | Тесты: store (фильтры/пагинация/risk_first, ревью happy-path/конфликты/append-only триггеры, экономика, лимит экспорта), drift (added/removed/changed, final_label, шум confidence, выбор пары прогонов), api E2E (все маршруты через httptest на реальном store: конверты ошибок, correlation id, ревью с аудитом, экспорт с аудитом до выдачи, лимит 409, дрейф, экономика, целостность цепочки после операций), engine (interrupted + финализация на отменённом ctx, ScanWithID). Заглушки `internal/api/doc.go` и `internal/verdict/drift/doc.go` заменены реализациями |

## 3. Ключевые решения

См. `docs/decisions/ADR-impl-stage-5b-rest-api.md` (D1–D10). Кратко:

- **До SSO actor = `api`, listen — loopback.** Требование аутентификации
  п. 11.2 закрывается инкрементом 5в; до него сервер по умолчанию не
  смотрит наружу, а аудит пишется с зарезервированным форматом actor.
- **Ревью атомарно с аудитом** — одной транзакцией; конфликты не оставляют
  следов ни в review_events, ни в audit_log.
- **Stop = ctx-отмена + `WithoutCancel`-финализация** — статус `interrupted`
  с чекпоинтами, без ложного partial по всем оставшимся таблицам.
- **Экспорт аудируется до выдачи** — отказанный лимитом экспорт не
  маскируется под совершённый.

## 4. Проверки (протокол — docs/validation/2026-10-19-stage-5b.md)

- `go build`, `go vet`, `gofmt` — чисто.
- `go test ./...` — все пакеты ok; `go test -race` по изменённым пакетам — ok.
- `make build` + `config validate` (ci.env) — OK; YAML `.golangci.yml` валиден.
- Live-smoke `zond serve`: health/ready/scans/verdicts/drift/export,
  конверты ошибок, `X-Request-ID` в ответе и access-логе, POST скана на
  недоступном стенде → 502 `source_unavailable` (стенд недоступен из этой
  сети — тот же блокер, что S1-9).

## 5. Изменённые файлы

Новые: `internal/verdict/store/migrations/0005_review_events.sql`,
`internal/verdict/store/{scans,verdicts,stats}.go`,
`internal/verdict/store/review_api_test.go`, `internal/verdict/drift/drift.go`
(+ drift_test.go; заглушка doc.go удалена), `internal/api/{server,
handlers_scans,handlers_verdicts,handlers_misc}.go`,
`internal/api/server_test.go`, `internal/scanengine/stop_test.go`,
`docs/decisions/ADR-impl-stage-5b-rest-api.md`.

Изменённые: `internal/verdict/store/store.go` (Ping),
`internal/scanengine/engine.go` (ScanWithID, interrupted, WithoutCancel),
`cmd/zond/main.go` (serve, engineRunner, engineConfig-рефакторинг runScan),
`.golangci.yml` (depguard). Заглушки `internal/api/doc.go` и
`internal/verdict/drift/doc.go` удалены (заменены реализациями).

## 6. Не вошло (следующие инкременты этапа 5)

- SSO SAML 2.0 (5в): аутентификация мутаций/экспорта, actor `sso:<subject>`,
  RBAC-матрица п. 11.3, события auth/authorization, `zond token` (api_tokens).
- Веб-UI (5г): страницы п. 11.3 поверх этого API, `/audit`, scheduler
  (cron-пересканы, retention аудита/кэша, async-экспорт по ссылке).
- API rate-limit 100 req/s (п. 11.2) — вместе с SSO-сессиями/токенами (5в);
  до появления субъектов лимитировать не по кому.
- Resume прерванного скана по чекпоинтам (п. 13) — `--resume`/POST resume.

## 7. Следующие шаги

1. Инкремент 5в: SSO SAML 2.0 (ADR-0011) — crewjam/saml, роли admin/viewer,
   JIT-прvisioning в `users`, Keycloak в compose (п. 16.5), API-токены со
   scope, rate-limit, события auth.
2. Инкремент 5г: веб-UI (п. 11.3) server-rendered + HTMX из embed.FS,
   страница `/audit` (admin), scheduler.
