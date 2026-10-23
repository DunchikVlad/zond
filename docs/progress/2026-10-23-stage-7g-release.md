# Прогресс: этап 7, инкремент 7г — релиз v0.1: security-гейт, релизный pipeline, smoke-контур

Дата: 2026-10-23
Исполнитель: агент сессии (этап 7 — «Харденинг и релиз v0.1»)
Статус: **done по коду/докам; тег v0.1 отложен** до прогона `make smoke`
на docker-хосте (D7: непроверенное не объявляется релизом). Следующие
шаги: `make smoke` на машине с docker → тег `v0.1` → push тега
(сработает release.yml) → LLM-метрики DoD при появлении стенда.

## 1. Цель

Blueprint п. 1059/1073–1095: security-чеклист п. 14, подпись/checksums/
SBOM, документация эксплуатации, smoke-чек, тег v0.1. П. 16.7: CI-ворота
(govulncheck, go-licenses). П. 15: харденинг контейнера, dev/demo-контур
`make smoke` ≤15 минут до первых вердиктов.

## 2. Что сделано

| Чанк | Результат |
|---|---|
| S7г-1 `f6b8527` | Security-гейт: 3 находки govulncheck в reachable-коде закрыты бампом (goxmldsig v1.6.0 — подпись SAML; go-jose/v4 v4.1.4; toolchain go1.27.3, go.mod); повторный прогон чист. Brute-force входа (п. 14): `auth.AttemptLimiter` (5 неудач/10 мин → блок 15 мин), 429 `rate_limited`, аудит `auth_rate_limited`, сброс при успехе. Idle-timeout SSO-сессии (п. 14, default 12 ч, скользящий LastSeen, SetIdleTimeout) |
| S7г-2 `3357a0f` | Makefile `release`: dist (linux/amd64, linux/arm64, windows/amd64; CGO_ENABLED=0, -trimpath), checksums (SHA256SUMS), sbom (syft) и sign (cosign keyless) с честным skip без инструмента. CI: govulncheck и go-licenses (бан GPL/Commons Clause; игноры: собственный модуль, segmentio/asm) — ворота п. 16.7. `.github/workflows/release.yml`: тег `v*` → матрица сборки → SHA256SUMS → SBOM (anchore/sbom-action) → cosign keyless (OIDC) → GitHub Release |
| S7г-3 `0de0d78` | Runbook'и 22.1: `pending-spike` (классификация причин роста pending: дрейф/LLM/hot-reload/mask/taxonomy; откат по diff-аудиту), `sso-login-failure` (metadata/часы 60с/entity_id/role_attribute/samesite; аварийный fallback с контролем и разбором входов). `docs/operations.md`: установка из релиза (сверка сумм/SBOM/cosign), конфиги и doctor, serve/scan, Vault, backup/restore, обновление, релизный процесс, перечень runbook'ов |
| S7г-4 `32bd3c8` | Пробелы п. 14 закрыты: `logging.SecretRedactor` (DSN-учётки, Authorization/Bearer, X-Admin-Token + явные env-секреты по конфигу и эвристике имён; обёртка slog-handler маскирует message и строковые атрибуты); redact-тест ловушек (п. 14.1 авто-тест). CSRF double-submit: cookie `zond_csrf` + `X-CSRF-Token` на мутациях, 403 при расхождении, htmx:configRequest в шаблоне; тесты защиты и HTMX-флоу |
| S7г-5 | Чеклист `docs/security/2026-10-23-release-v0.1-checklist.md`: матрица п. 14 покомпонентно со статусами и подтверждениями; открытые пробелы явно (circuit breaker 13.2, SIEM-sink-опция, шифрование тома — операторский чек, LICENSE-файл, scratch-образ, LLM-метрики) |
| S7г-6 `d3cf168` | Smoke-контур: `deploy/Dockerfile` (scratch, non-root UID 65534, CA, -trimpath), `deploy/docker-compose.yml` (app+ClickHouse+MongoDB+seed, healthcheck-гейтинг, профиль smoke-scan с общим томом БД — вердикты видны UI), seed (PII/негативы), smoke-конфиги (валидны), Makefile `smoke`/`smoke-clean`. Ритуал: учебное восстановление пройдено (backup → restore --check, hash-chain сходится) |

## 3. Ключевые решения

См. `docs/decisions/ADR-impl-stage-7g-release.md` (D1–D7). Кратко:
уязвимости бампом не подавлением (D1); лимитер in-memory по IP (D2);
redactor = паттерны + явные env-значения (D3); CSRF double-submit (D4);
релиз авторитетно в CI на тег (D5); smoke — один образ и общий том (D6);
тег — только после прогона smoke (D7).

## 4. Проверки (протокол — docs/validation/2026-10-23-stage-7g.md)

- `make ci`, `make config-check` — зелёные; race по затронутым
  (auth, api, web, logging) — ok.
- govulncheck: 3 находки → бамп → 0 в вызываемом коде. go-licenses:
  чисто с обоснованными игнорами.
- `make release`: 3 бинари (ELF static / exe работает, version из
  ldflags) + SHA256SUMS; syft/cosign — честный skip.
- Smoke-конфиги валидны (sources=2 agents=2 labels=19); compose YAML —
  парсится. Учебное восстановление пройдено.
- `make smoke` и release.yml — **не прогнаны**: docker в сессии
  отсутствует. Это следующий шаг (D7).

## 5. Известное и ограничения

- Docker/compose-подъём не выполнялся в сессии — прогон smoke и выпуск
  тега v0.1 — на машине с docker.
- Открытые пробелы чеклиста (раздел 3 checklist): circuit breaker (13.2),
  SIEM-sink (опция п. 14.2), LICENSE-файл (выбор — продуктовое решение),
  LLM-метрики DoD (F1 семантики, $/1000) — без стенда.
- release.yml написан по спецификации GitHub Actions, локально не
  исполнялся (сработает на push тега).

## 6. Следующий шаг

`make smoke` на docker-хосте → зелёный прогон в validation →
`git tag v0.1 && git push origin v0.1` (release.yml соберёт артефакты).
Параллельно: `make bench` (п. 16.8), `cmd/eval run -llm` при стенде,
вопрос LICENSE владельцу.
