# Прогресс: S9-2 — полный per-column LLM evidence

Дата: 2026-10-26
Статус: **done** (код и тесты — коммит S9-2 этой даты).
Основание: `docs/progress/2026-10-25-stage-9-plan.md`, раздел 3.

## 1. Что было

Итоговый вердикт ансамбля отличался от ответа LLM, но сохранялось только
`evidence.llm = {reason_ru, agent, model}`; ответ классификатора (label,
confidence, sensitivity), ответ верификатора без идентичности агента,
экономика вызова и состояние LLM-обработки колонки в вердикте не фиксировались.
При попадании в кэш терялись `reason_ru`/`sensitivity`, а `PromptVersion`
вердикта оставался пустым (дефект hit-ветки).

## 2. Что сделано

### Расширенная учётная запись вызова (миграция `0011_llm_evidence.sql`)

`agent_calls` получила колонки `operation` (classify|verify), `answer_label`,
`answer_confidence`, `answer_sensitivity`, `reason_ru`, `error` (обрезка до 300
символов). Все вызовы — включая cache_hit и error — пишутся в той же транзакции
с вердиктом (п. 13) и с тем же парным аудит-событием `agent_call` (в Details
добавлены operation и answer_label). Новый метод `ListAgentCallsByVerdict` —
переход от колонки к её вызовам.

### Статус LLM-обработки колонки

Новое поле `verdicts.llm_status` (тип `verdict.LLMStatus`, 7 значений:
not_called, called, cache_hit, small_sample, cluster_propagated,
budget_exceeded, error). Движок выставляет статус во всех ветках каскада:
кластер-распространение (приоритет над small_sample), budget-стоп, small_sample
в `finalizeVerdict`, cache_hit/called/error внутри `llmClassify`, fallback
not_called. Ошибка верификатора не меняет статус колонки — классификатор уже
отработал, ошибка видна в записи вызова.

Исторические строки бэкфиллятся только по фактам evidence (порядок:
cluster_propagated → budget_exceeded → small_sample → cache_hit → called);
недетектируемое не выдумывается, остаётся пустым («неизвестно»).

### Эквивалентность cache hit/miss

`cachedLLMVerdict` теперь хранит `sensitivity` и `reason_ru`; при hit
`v.PromptVersion` заполняется из записи кэша (дефект закрыт), а
`evidence["llm"]` строится тем же кодом, что и при промахе (токены/стоимость/
латентность нулевые — сетевого вызова не было). Старые записи кэша декодируются
с пустым объяснением (раньше оно кэшем просто не сохранялось).

### Evidence и показ

`evidence["llm"]` — label, confidence, sensitivity, reason_ru, prompt_version,
tokens_in/out, cost_usd, latency_ms, agent, model. `evidence["llm_verify"]` —
вердикт/лейбл/confidence/reason_ru плюс agent, model, prompt_version и экономика.
Экономичный каскад не изменён: LLM по-прежнему пропускается при уверенных
слоях 0–1, кластерном распространении, малом сэмпле и budget-стопе — теперь
каждый пропуск имеет явный статус.

API: `llm_status` в DTO вердикта; фильтр `?llm_status=` в списке (валидация,
невалидный → 400); новый `GET /api/v1/verdicts/{id}/agent-calls` (ActionView,
404 `verdict_not_found`). UI: select фильтра, колонка «LLM», раскрытие
«вызовы LLM» с ленивой HTMX-подгрузкой фрагмента `/verdicts/{id}/calls`
(экранирование html/template), строки evidence с экономикой вызова.

## 3. Проверка и границы

`make ci` зелёный; полный `make test-race` — см.
`docs/validation/2026-10-26-stage-9-2.md`; безопасность —
`docs/security/2026-10-26-stage-9-2.md`. Живой стенд не использовался:
приёмка через реальные HTTP-обработчики, SQLite-миграции и fake-LLM движка.
