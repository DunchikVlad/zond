# Прогресс: S9-3 — пользовательский промпт на скан

Дата: 2026-10-26
Статус: **done** (код и тесты — коммит S9-3 этой даты).
Основание: `docs/progress/2026-10-25-stage-9-plan.md`, раздел 4.

## 1. Что было

UI/API принимали только source/profile, system-промпт статический, включение
LLM зависело только от глобального `serve -llm`, ключ кэша — только от
глобальной `prompts.Version`. Prompt-контракт (blueprint п. 5.3) и ADR изоляции
требовали дополнения перед реализацией — обновлены в этом же инкременте
(«-док» коммит).

## 2. Что сделано

### Prompt-контракт и изоляция

- blueprint п. 5.3: блок «Пользовательская инструкция на скан» — доверенный
  ввод (RBAC scan), append-only блок `<operator_instruction>` после
  защищённых правил, неотменяемость enum/схемы/анти-инъекции зафиксирована
  текстуально; п. 10.5: `user_prompt_hash` в ключе кэша; п. 11.1: колонки
  scans; п. 13: resume сверяет и воспроизводит промпт; таблица угроз: строка
  про вредоносную инструкцию.
- ADR-security-llm-isolation, дополнение S9-3: изоляция не ослаблена —
  инструкция идёт в system (доверенный канал), конверт без идентификаторов
  инфраструктуры, лимиты на границе, прозрачность (кэш/provenance/аудит).
- `prompts.Version` = "2" (структура промпта изменена — кэш инвалидирован
  естественно через ключ).

### Пакет prompts

`NormalizeUser` (trim; ≤2000 символов; NUL запрещён; fail-closed),
`UserHash` (пустая инструкция → пустой хэш, ключ кэша прежней длины),
`SystemWithInstruction`/`VerifierSystemWithInstruction` (блок
`<operator_instruction>` с фиксацией неотменяемости правил).

### Путь опции: UI/API/CLI/scheduler → runner → scanengine → agentproxy

- Единый `scanengine.ScanOptions{Source, Profile, Actor, UserPrompt, LLM *bool}`
  заменил позиционные `Start(source, profile, actor)` в интерфейсах
  api.ScanRunner, web.ScanRunner, scheduler.ScanStarter.
- agentproxy: опция `WithInstruction` — инструкция в system-промпт обоих
  прокси (classify и verify); прокси собираются на прогон, снимок неизменяем,
  hot-reload детекторов/источников на действующий прогон не влияет.
- Per-scan LLM: `llm` в API (`*bool`), select в UI (default/вкл/выкл),
  отсутствие — поведение сервера; fingerprint включает и флаг, и хэш.
- Scheduled-прогоны — всегда стандартный (пустой) промпт и default-LLM
  (явное правило плана).

### Граница и аудит

- REST: лимит тела 1 МБ, `DisallowUnknownFields`, нормализация с 400 на
  ошибке. Web-форма: textarea (maxlength 2000) + select LLM. CLI: `-prompt`.
- Аудит scan_start: `prompt_hash`, `prompt_len`, `llm` — без полного текста
  (ADR-0013). Текст хранится в `scans.prompt_text`.

### Provenance и resume

- Миграция `0012_scan_prompt.sql`: `scans.prompt_base_version`,
  `prompt_hash`, `prompt_text`, `llm_enabled`. Старые строкы — пустые
  значения (не угадываются).
- `ValidateResume` сверяет оба поля fail-closed (legacy-пустые несовместимы).
  Resume (CLI/REST/UI) воспроизводит `prompt_text` и `llm_enabled` исходного
  прогона; `-prompt` с `-resume` в CLI отклоняется.
- Ключ кэша: `sha256(... | user_prompt_hash | fingerprint(values))` —
  разные инструкции не делят кэш (тест: одинаковые значения, другой промпт →
  повторный сетевой вызов).

## 3. Проверка и границы

`make ci` зелёный; полный `make test-race` — см.
`docs/validation/2026-10-26-stage-9-3.md`; безопасность —
`docs/security/2026-10-26-stage-9-3.md`. Живой стенд и Kimi не использовались:
приёмка через реальные HTTP-обработчики, SQLite-миграции, fake-LLM прокси
(включая изоляционный тест п. 16.3 с инструкцией) и fake-коннекторы движка.
