# Эксплуатация zond (релиз v0.1)

Операционный гид по установке и сопровождению инстанса. Источник правды
по продукту — `blueprint.md` (п. 11–15); здесь — практические команды.
Диагностика инцидентов — runbook'и в `docs/runbooks/`.

## 1. Артефакты и установка

Релиз (GitHub Releases, тег `v*`): три платформы + три обязательных
артефакта (blueprint п. 15):
- `zond-<v>-<goos>-<goarch>[.exe]` — бинарник (static, `-trimpath`);
- `SHA256SUMS.txt` — контрольные суммы;
- `zond-<v>-sbom.spdx.json` — SBOM (syft, SPDX-JSON);
- `*.sig`/`*.pem` — подписи cosign (keyless; проверка:
  `cosign verify-blob --signature f.sig --certificate f.pem f`).

Установка:
```bash
sha256sum -c SHA256SUMS.txt           # сверка
install -m 0755 zond-v0.1-linux-amd64 /usr/local/bin/zond
```
Требования: Linux/Windows, amd64/arm64; SQLite — файл на диске
(шифрование тома — требование п. 14); секреты — только env/Vault.

## 2. Конфигурация

Три файла (строгая схема, ADR-0009; секретов в файлах нет — `${ENV}`):
- `configs/connections.yaml` — источники (`dsn`/`uri`/`ref`), `sso`,
  `vault` (ADR-0012), `backup` (п. 15.2). Меняется только рестартом.
- `configs/detectors.yaml` — пороги, агенты, лимиты; hot-reload с
  аудитом diff (ADR-0014).
- `configs/taxonomy.yaml` — лейблы, semver.

Проверка до старта:
```bash
set -a && . ./configs/ci.env && set +a   # или реальные env
zond config validate
zond doctor [-online]                    # preflight, п. 15.3
```
`doctor -online` обязателен перед вводом в эксплуатацию: диск ≥2× БД,
hash-chain аудита, источники (ping/probe), агенты (env/egress/пробник),
TLS-сертификат SP, Vault (аутентификация + чтение каждого секрета).

## 3. Запуск

```bash
zond serve -config configs -db /var/lib/zond/zond.db \
  -addr 127.0.0.1:8080 [-llm] [-strict]
```
- `-strict` — preflight doctor блокирует старт при FAIL (п. 15.3);
- до SSO доступ открыт (actor `api`, ADR-impl-5б); с `sso.enabled: true` —
  SAML 2.0 (п. 11.3), API-токены `zond token issue`;
- встроенный планировщик: пересканы по `schedule` источников, retention
  (п. 15.4), TTL кэша, алертинг (п. 17), расписание backup (п. 15.2).

Разовый скан (CI/one-shot):
```bash
zond scan -source <имя> [-profile quick|deep] [-llm]
```
Аудит всегда: `zond audit verify` (hash-chain), `zond audit export`.

## 4. Секреты

- Без Vault: `${ENV}`-интерполяция (имена переменных — в конфиге,
  значения — в env инстанса).
- Vault (ADR-0012, п. 12.1): источники со `ref`; doctor проверяет
  аутентификацию и чтение каждой записи. Демо-контур и настройка:
  `deploy/docker-compose.vault.yml`, runbook
  `docs/runbooks/vault-demo-contour.md`.
- LLM-ключи агентов — env по `api_key_env` (п. 5.3).

## 5. Резервное копирование и восстановление (п. 15.2)

```bash
zond backup -out /backups/zond/zond-$(date +%F).db   # VACUUM INTO, online
zond restore -from <копия> -to <пустой каталог>      # migrate + hash-chain
```
Расписание: `backup.schedule/dir` в connections.yaml (попытки ok/fail —
в аудит; алерт `backup_failed`, RPO 24 ч). Копии — вне инстанса
(S3/WORM). Учебное восстановление — раз в релиз (DoD п. 22); детали —
`docs/runbooks/restore-from-backup.md`.

## 6. Наблюдаемость

- UI: `/scans`, `/review`, `/drift`, `/cost` (метрики инстанса), `/alerts`;
- expvar: `GET /debug/vars` (auth через API-mux): `zond/process`,
  `zond/store`;
- алертинг: события в UI + webhook `ZOND_ALERT_WEBHOOK` (п. 17);
- логи: JSON в stdout/stderr, correlation id (п. 14.1), redact-ловушки
  покрыты тестами.

## 7. Обновление

1. `zond doctor` — инстанс здоров; `zond backup` — копия свежая.
2. Заменить бинарник, `zond config validate` (миграции SQLite — только
   вперёд, п. 18.1; `goose up` применяется при открытии store).
3. Рестарт; `zond doctor`; сверка версий: `detectors_version`,
   `taxonomy_version`, версия бинарника фиксируются в каждом скане
   (provenance, п. 18.1).
Откат — прежним бинарником на прежней БД (копия перед обновлением).

## 8. Релизный процесс (для мейнтейнеров)

1. Чеклист п. 14 — `docs/security/` (security-гейты: govulncheck,
   go-licenses — в CI).
2. Тег `vX.Y.Z` → CI `.github/workflows/release.yml`: кросс-сборка →
   SHA256SUMS → SBOM → cosign-подпись → GitHub Release.
3. Учебное восстановление из релизной копии (DoD п. 22).

## 9. Интеграционный контур для разработки

`make smoke` — compose-контур (app + ClickHouse + MongoDB + seed) и
скан quick-профилем до первых вердиктов (DoD: ≤15 мин с нуля).
Демо-контуры: Keycloak (`deploy/docker-compose.keycloak.yml`),
Vault (`deploy/docker-compose.vault.yml`).

## 10. Runbook'и реагирования

- `scan-stuck-running.md` — скан завис в `running`;
- `pending-spike.md` — массовый рост pending;
- `llm-unavailable.md` — деградация LLM;
- `sso-login-failure.md` — вход SSO, fallback admin-токен;
- `audit-hash-chain-broken.md` — разрыв hash-chain;
- `restore-from-backup.md` — восстановление из копии;
- `vault-demo-contour.md` — подъём Vault и деградация секретов (R11).
