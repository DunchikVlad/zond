# ADR-impl: S9-1 — источники, qualified identity и resume provenance

Дата: 2026-10-26
Статус: accepted
Код: `691d0f4`
Связь: ADR-0006 (SQLite), ADR-0009 (конфиг), ADR-0013 (аудит),
ADR-impl-stage-8-7-sources-ui, blueprint п. 5.4, 11–13.

## D1. Изменение источника — компенсируемая транзакция под mutex

**Выбор:** read/modify/validate/write/apply/audit выполняется последовательно
под process-local mutex. После записи файла сначала hot apply, затем обязательный
аудит. Apply error → restore файла; audit error → restore файла + повторный apply
старого состояния. Temp создаётся через `os.CreateTemp` в каталоге назначения.

**Почему:** запись без аудита нарушает ADR-0013, а оставленный неприменённый файл
ломает следующий restart. Post-apply audit сохраняет смысл success-событий
`source_add/update/delete`; компенсация не требует второго источника правды.

**Граница:** внешние writers и multi-node не сериализуются — проект single-instance.

## D2. Полная схема и строгие секреты при редактировании

**Выбор:** strict decode + `Connections.Validate`; ровно один из dsn/uri/ref;
пароль или вся строка подключения — только целая `${ENV_NAME}`. Vault ref и
resource limits входят в Node-round-trip.

**Почему:** локальная проверка SourceEntry недостаточна: дубли, сломанный Vault
и глобальные блоки видны только на итоговом документе. Частичная ENV-строка
может содержать открытый фрагмент секрета и отклоняется.

## D3. Единая каноническая qualified identity, без обратного разбора

**Выбор:** `TableRef.QualifiedName()` = escaped `schema.table`; `\` → `\\`,
`.` → `\.` в каждом компоненте. В store/API попадает эта строка; драйверы
продолжают получать исходную пару Schema/Name. Verdict ID — SHA-1 над
length-prefixed tuple.

**Отклонено:** naive `schema + "." + name` конфликтует на именах с точками;
разбор qualified string обратно создаёт второй, потенциально расходящийся SPI.

**Совместимость:** `scans.table_identity_version` отмечает новые прогоны.
Старые table/ID не переписываются: схему восстановить неоткуда, а уже
конфликтовавшие вердикты невозможно достоверно реконструировать.

## D4. Resume только при совпадающем provenance

**Выбор:** сохранять и сравнивать config fingerprint, taxonomy/detectors/binary
versions; ошибка содержит все различия. Пустые legacy-поля = unknown = отказ.
Проверка выполняется в CLI/runner синхронно и повторно в engine перед SaveScan.

**Fingerprint:** SHA-256 JSON effective detectors+taxonomy+source+profile+LLM.
Пароль DSN/URI удалён; runtime cancel/breaker/actor/resume не входят. Поэтому
изменение содержимого при неизменном текстовом version всё равно обнаруживается,
а ротация пароля не создаёт ложный отказ.

**Snapshot:** runner берёт bundle один раз до подключения и использует его для
fingerprint, LLM, meta и engine. Hot-reload не меняет действующий прогон.

## D5. Resume по ID в REST/UI, прежний сценарий CLI

**Выбор:** `POST /api/v1/scans/{id}/resume` и аналогичный UI action создают новый
scan со старым profile; CLI `-resume` по-прежнему выбирает последний
partial/interrupted источника. Несовместимость API — 409 `resume_incompatible`
с `mismatches[]`.

**Почему:** UI/API должны продолжать явно выбранную историческую запись, а
существующий операторский CLI-сценарий не требовал изменения. Done-вердикты не
копируются в новый scan: чекпоинты используются только для пропуска таблиц,
как и прежде.
