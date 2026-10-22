# Прогресс: этап 6, инкремент 6в — метрики и наблюдаемость

Дата: 2026-10-22
Исполнитель: агент сессии (этап 6 — «Качество и экономика», blueprint п. 21)
Статус: **done** (S6в, этап 6 закрыт полностью). Следующие: этап 7 —
харденинг (doctor п. 15.3, backup п. 15.2 + алерт backup_failed, Vault
ADR-0012, релиз v0.1); либо прогон `cmd/eval run -llm` при появлении
LLM-стенда; `make bench` (п. 16.8) — отдельной задачей.

## 1. Цель

Blueprint п. 17: бизнес-метрики (доля решённого без LLM, токены/$ на скан,
доля pending→confirmed), технические (latency p50/p95, кэш-попадания,
retry/llm_unavailable), экспозиция (expvar /debug/vars, дашборды) и
встроенный алертинг (budget_exceeded, рост pending R9, серия
llm_unavailable, разрыв hash-chain; backup_failed — с инкрементом бэкапа,
этап 7).

## 2. Что сделано

| Чанк | Результат |
|---|---|
| S6в-1 | `observe.Meter` — атомарные счётчики процесса (сканы по статусам, LLM-вызовы/ошибки/кэш/кластеры, токены, $×1e6, вердикты); инструментация `scanengine` (`recordCall` — единая воронка вызовов, `finish`, cluster-propagated); `GET /debug/vars` за ActionView (реестр expvar: `zond/process` + stdlib cmdline/memstats), публикация идемпотентна |
| S6в-2 | `store.LLMWindowStats` (агрегаты agent_calls за окно; токены/$ — по ok-вызовам, конвенция движка; latency-выборка ORDER BY), `LLMErrorStreak` (серия ошибок + агент последней), `LatestScanOverviews` (последний прогон источника: pending, llm-колонки, no_llm_share), `ReviewActionCounts`; `observe.BuildSnapshot` — снимок инстанса (p50/p95 ближайшим рангом, cache-hit share, unavailable=streak>5, сводка по источникам, доля confirmed); `GET /api/v1/stats/metrics` (ActionView); инстанс-блок на `/cost`; `expvar zond/store` (агрегаты на скрапе, публикация в serve) |
| S6в-3 | Алертинг: миграция 0007 `alerts` (дедуп открытых по (rule,target), продление last_seen_at, авто-закрытие при угасании); `audit.CatAlert` (raise/resolve, actor scheduler, п. 14.2); правила: `budget_exceeded` (последний прогон источника), `pending_backlog` (R9, default 500 на источник), `llm_unavailable` (>5 ошибок подряд, цель agent:<id>), `audit_chain_break` (критично, AuditVerify); `observe.Evaluator` — проход правил с изоляцией ошибок и recover (не роняет расписание), закрытие угасших; запуск из scheduler'а (`WithAlerts`, default `*/5 * * * *`); webhook-доставка событий raised/resolved из `ENV ZOND_ALERT_WEBHOOK` (п. 12/20: fail-closed — таймаут 5с, без ретраев, ошибки в лог); depguard обновлён (net/http в internal/observe — исходящий webhook, не LLM); UI `/alerts` (viewer: журнал, счётчик открытых, фильтр state), ссылка в навигации; `/debug/vars` промонтирован на корневом mux serve (было: unreachable — API-mux живёт под /api/) |

## 3. Ключевые решения

См. `docs/decisions/ADR-impl-stage-6v-observe.md`. Кратко:

- **Meter как процессные счётчики + Snapshot как store-агрегаты**: разные
  времена жизни (перезапуск vs хранилище) и разные читатели; оба — под
  одним `/debug/vars` (zond/process, zond/store).
- **Алерты — таблица с дедупом открытых**, а не поток событий: оператору
  нужен актуальный список «что сейчас горит», а не лог дублей; история
  сохраняется (resolved), события raise/resolve дублируются в audit
  (append-only, п. 14.2) и webhook.
- **Пороги и без LLM-стенда**: правила опираются на store (agent_calls,
  scans, audit) и полностью работают без живого LLM; unavailable-метрики
  считаются по записям вызовов.

## 4. Проверки (протокол — docs/validation/2026-10-22-stage-6v.md)

- `go build`, `go vet`, `gofmt -l .` — чисто; `golangci-lint run` —
  0 issues (depguard-исключение internal/observe задокументировано).
- `go test ./...` — все пакеты ok; `go test -race` затронутых пакетов —
  ok (гонка счётчика в тесте scheduler поймана race-детектором, вылечена
  atomic'ом).
- `make ci`, `make config-check` — зелёные.
- Smoke `zond serve` (ci.env, loopback): /api/health, /cost, /alerts,
  /api/v1/stats/metrics, /debug/vars (zond/process + zond/store) — 200.

## 5. Изменённые файлы

Новые: `internal/observe/{meter.go,meter_test.go,snapshot.go,snapshot_test.go,alerts.go,alerts_test.go,webhook.go}`,
`internal/verdict/store/{observability.go,observability_test.go,alerts.go,alerts_test.go}`,
`internal/verdict/store/migrations/0007_alerts.sql`,
`internal/web/templates/alerts.html`.
Изменённые: `internal/audit/audit.go` (CatAlert + комментарий),
`internal/scanengine/{engine.go,observe_test.go}`, `internal/api/{server.go,handlers_misc.go,server_test.go}`,
`internal/web/{server.go,templates/_header.html,templates/cost.html}`,
`internal/scheduler/{scheduler.go,scheduler_test.go}`, `cmd/zond/main.go`,
`.golangci.yml`, `architecture.md`.
go.mod не менялся.

## 6. Не вошло (следующие инкременты)

- Этап 7: doctor (п. 15.3), backup (п. 15.2) + правило `backup_failed`
  (п. 17), Vault (ADR-0012), релиз v0.1.
- Прогон `cmd/eval run -llm` против живого LLM-стенда ($-отчёт, п. 16.6).
- `make bench` (п. 16.8) — нагрузочный слоя 1, метрика в отчёт.
- OTLP-трейсы (п. 17 «опционально») — при потребности, expvar покрывает
  базовую экспозицию.
