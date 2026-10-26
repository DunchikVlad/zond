# Прогресс: S9-1 — корректность источников, таблиц и resume

Дата: 2026-10-26
Статус: **done** (код и тесты `691d0f4`).
Основание: `docs/progress/2026-10-25-stage-9-plan.md`, раздел 2.

## 1. Безопасное редактирование `/sources`

- HTMX-ответ проверки подключения экранирует имя источника и текст ошибки.
- `SourceEditor.ValidateAll` после strict decode вызывает полную
  `Connections.Validate` без раскрытия ENV.
- Save/delete сериализованы mutex'ом на всём пути read → modify → write →
  hot apply → audit. Временные файлы уникальны, замена атомарна, `.bak` сохранён.
- Применение и аудит fail-closed: ошибка apply откатывает файл; ошибка аудита
  откатывает файл и повторно применяет старое состояние к runtime. Сообщения
  «вступит после рестарта» больше не используются.
- Пароль принимается только как целая `${ENV_NAME}`-ссылка; DSN/URI целиком
  также может быть ENV-ссылкой. Смешанный plaintext и составные ссылки запрещены.
- В форму и Node-round-trip добавлены Vault `ref`, `max_concurrent_scans`,
  `max_concurrent_tables`, `query_timeout_s`. Числа парсятся строго и пишутся
  YAML-узлами `!!int`; ноль удаляет поле и означает default.

## 2. Полное имя таблицы

`connector.TableRef.QualifiedName()` формирует `schema.table`; для MongoDB это
`database.collection`. Обратная косая черта и точка внутри компонентов
экранируются, поэтому пары (`a.b`,`c`) и (`a`,`b.c`) не конфликтуют. Драйверы
получают исходные `Schema`/`Name`, а не разбирают строку обратно.

Qualified name проходит через чекпоинты, resume, verdict ID, `verdicts`,
drift, REST/UI и экспорт. ID вердикта использует SHA-1 над length-prefixed
`(scan_id, table, path)`, исключая неоднозначную конкатенацию.

Миграция `0010_scan_provenance.sql` добавляет `table_identity_version=2` для
новых прогонов. Исторические имена и ID не переписываются: исходная схема в
старых строках отсутствует, поэтому достоверный backfill невозможен.

## 3. Resume provenance и API/UI

В `scans` сохраняются `config_fingerprint`, `taxonomy_version`,
`detectors_version`, `binary_version`. Fingerprint — SHA-256 канонического JSON
эффективных detectors/taxonomy, выбранного источника, профиля и режима LLM;
пароль DSN/URI исключён, поэтому его ротация не ломает resume.

CLI `-resume`, REST и UI перед продолжением проверяют все четыре значения.
Ошибка содержит полный стабильно упорядоченный список различий. Пустые поля
legacy-скана означают unknown и отклоняются fail-closed. Новый `scans` при
ошибке не создаётся. Runner фиксирует один bundle snapshot до подключения и
использует его для fingerprint, LLM и всего прогона.

Добавлено:

- `POST /api/v1/scans/{id}/resume` → 202 `{scan_id,resume_from,status}`;
- 404 для отсутствующего ID, 409 для неподходящего статуса;
- 409 `resume_incompatible` с `details.mismatches[]`;
- `POST /scans/{id}/resume` и кнопки для partial/interrupted в списке и карточке;
- существующий CLI-сценарий без ID сохранён.

## 4. Проверка и границы

`make ci`, `make config-check`, полный `make test-race` зелёные. Детали —
`docs/validation/2026-10-26-stage-9-1.md`; безопасность —
`docs/security/2026-10-26-stage-9-1.md`; решения —
`docs/decisions/ADR-impl-stage-9-1-correctness.md`.

Живой стенд БД/Kimi в этой сессии не использовался. Приёмка выполнена через
реальные HTTP-обработчики, SQLite-миграции и in-memory connector; внешний
стендовый smoke остаётся операционной проверкой при доступности контура.
