# Прогресс: этап 7, инкремент 7в — Vault: резолвер секретов (ADR-0012, п. 12.1)

Дата: 2026-10-23
Исполнитель: агент сессии (этап 7 — «Харденинг и релиз v0.1»)
Статус: **done** (S7в). Следующий: S7г — релиз v0.1 (security-чеклист
п. 14, подпись/checksums/SBOM, документация эксплуатации, smoke-чек,
тег). Отдельно: `make bench` (п. 16.8), прогон `cmd/eval run -llm` при
появлении LLM-стенда.

## 1. Цель

Blueprint п. 12.1 (ADR-0012): секреты подключений из HashiCorp Vault
без хранения на сервере — kv-v2 и dynamic leases (авто-ротация,
продление фоновой горутиной), чтение в момент установления коннекта,
события резолва/ротации в аудит без значений (п. 14.2), режим
деградации при недоступности Vault (R11: кэш лизы до истечения, fail
конкретного источника, не всего скана). Проверка vault в doctor
становится реальной (обещание S7а, ADR-impl-stage-7a D5).

## 2. Что сделано

| Чанк | Результат |
|---|---|
| S7в-1 | `internal/secrets`: интерфейс `Resolver` (Resolve/Close), сентинел `ErrUnavailable`, хук `AuditHook` (resolve/lease_renew/lease_revoked/renew_failed без значений). Реализация `Vault` поверх `hashicorp/vault/api` v1.16.0: kv-v2 (`key` — готовый DSN/URI, unwrap `data.data`, откат на плоский ответ) и dynamic (`dsn_template` с `{{username}}`/`{{password}}`); кэш только лиз (до истечения), renew в середине срока, 403 на renew = отзыв (кэш сброшен), иная ошибка = кэш до истечения; `Authenticate` (token из env \| kubernetes login по JWT сервис-аккаунта); `NewFromConfig` — единая точка cmd/doctor. `config`: `Source.Ref`, блок `Vault{enabled,address,auth,secrets}`, валидация fail-fast (ровно один из dsn/uri/ref; ref↔secrets двусторонне; key\|dsn_template взаимоисключающи и оба плейсхолдера обязательны; токен в конфиге отвергается строгой схемой) |
| S7в-2 | Проводка: `scan`, `engineRunner.Start` (API + шедулер), `doctor` — `resolveSourceDSN` через резолвер для ref-источников; `ErrUnavailable` → источник failed с причиной `vault_unavailable` (API 502 source_unavailable). Аудит: `audit.CatSecrets`, actor resolve — инициатор из контекста, продление лиз — `scheduler` (п. 14.2); doctor аудит не пишет (read-only). doctor: код `vault` (аутентификация) и `vault.read` (реальное чтение каждой записи secrets); ref-источники: offline SKIP / auth-фейл FAIL / сбой резолва FAIL; резолвер закрывается после прогона. Демо-контур: `deploy/docker-compose.vault.yml` (dev Vault, loopback, root token из env) + runbook `docs/runbooks/vault-demo-contour.md` (kv-v2 и dynamic database engine, конфиг zond, проверка, деградация R11); пример `vault:` в `configs/connections.yaml` (закомментирован) |

## 3. Ключевые решения

См. `docs/decisions/ADR-impl-stage-7v-vault.md`. Кратко:

- **dsn_template для dynamic** (D1) — хост/БД не секреты, живут в
  конфиге; подстановка username/password из лизы.
- **Кэш только для лиз** (D2) — kv-v2 дочитывается на каждый коннект,
  чтобы не скрывать операторскую ротацию.
- **403 = отзыв, иное = кэш до истечения** (D3) — fail-closed/fail-safe
  по характеру ошибки; «прозрачный реконнект» — на границе коннектов.
- **Аудит фактами без значений** (D4); actor продления — scheduler.
- **doctor читает каждый секрет реально** (D7) — единственная честная
  online-проверка.

## 4. Проверки (протокол — docs/validation/2026-10-23-stage-7v.md)

- `go build`, `go vet`, `gofmt` — чисто; `make ci` — зелёный;
  `make config-check` — OK; `go test -race ./...` — ok.
- Unit: `internal/secrets` (13 тестов: kv2/dynamic, кэш/истечение,
  renew/отзыв/трансиентный сбой, аудит без значений, auth token/k8s,
  NewFromConfig), `internal/config` (валидный vault + 11 negative-кейсов
  + токен в конфиге), `internal/doctor` (online OK/auth fail/offline).
- Smoke против fake Vault (httptest через `go run`, без docker):
  `zond doctor -online` — `vault OK (аутентификация method=token)`,
  `vault.read OK (kv-v2)`; с остановленным стендом — честный FAIL
  «vault недоступен». `zond scan` + `zond audit export -category
  secrets` — запись resolve (actor cli, только ref+path) в hash-chain.
- Живой dev-контур (compose) не поднимался: docker в окружении сессии
  отсутствует — compose + runbook готовы, поведение покрыто fake-стендом.

## 5. Известное и ограничения

- Реконнект внутри длительного скана при отзыве лизы — вне скоупа:
  коннектор открывается на скан; следующий коннект возьмёт новый
  секрет (D3).
- Kubernetes-аутентификация покрыта fake-стендом (логин), но не
  живым кластером — в окружении сессии его нет.
- Renew в середине срока; Vault не вернул срок — default 1 мин.
- `make test -race ./...` дал один флаки `internal/audit` под
  параллельной нагрузкой (не затронут этим инкрементом; в изоляции и
  повторных прогонах — стабильно ok).

## 6. Следующий шаг

S7г — релиз v0.1: security-чеклист п. 14, подпись/checksums/SBOM,
документация эксплуатации, smoke-чек, тег.
