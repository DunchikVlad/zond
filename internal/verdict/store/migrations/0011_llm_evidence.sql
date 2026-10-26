-- +goose Up
-- S9-2: полный per-column LLM evidence. Расширенная учётная запись вызова
-- (операция, ответ агента, объяснение, ошибка) и статус LLM-обработки
-- колонки на вердикте (blueprint S9 п. 3). Старые строки бэкфиллятся только
-- по фактам evidence — недетектируемое не выдумывается.

ALTER TABLE agent_calls ADD COLUMN operation TEXT NOT NULL DEFAULT '';
ALTER TABLE agent_calls ADD COLUMN answer_label TEXT NOT NULL DEFAULT '';
ALTER TABLE agent_calls ADD COLUMN answer_confidence REAL NOT NULL DEFAULT 0;
ALTER TABLE agent_calls ADD COLUMN answer_sensitivity TEXT NOT NULL DEFAULT '';
ALTER TABLE agent_calls ADD COLUMN reason_ru TEXT NOT NULL DEFAULT '';
ALTER TABLE agent_calls ADD COLUMN error TEXT NOT NULL DEFAULT '';

ALTER TABLE verdicts ADD COLUMN llm_status TEXT NOT NULL DEFAULT '';
CREATE INDEX idx_verdicts_llm_status ON verdicts(scan_id, llm_status);

-- Бэкфилл исторических строк только по фактам evidence (порядок важен,
-- каждый UPDATE перезаписывает только ещё пустые; не угадываем недетектируемое):
UPDATE verdicts SET llm_status='cluster_propagated' WHERE llm_status='' AND evidence LIKE '%"cluster_propagated":true%';
UPDATE verdicts SET llm_status='budget_exceeded' WHERE llm_status='' AND evidence LIKE '%"budget_exceeded":true%';
UPDATE verdicts SET llm_status='small_sample' WHERE llm_status='' AND evidence LIKE '%"reason":"small_sample"%';
UPDATE verdicts SET llm_status='cache_hit' WHERE llm_status='' AND evidence LIKE '%"llm_cache"%';
UPDATE verdicts SET llm_status='called' WHERE llm_status='' AND evidence LIKE '%"llm":%';

-- +goose Down
DROP INDEX IF EXISTS idx_verdicts_llm_status;
ALTER TABLE verdicts DROP COLUMN llm_status;

ALTER TABLE agent_calls DROP COLUMN error;
ALTER TABLE agent_calls DROP COLUMN reason_ru;
ALTER TABLE agent_calls DROP COLUMN answer_sensitivity;
ALTER TABLE agent_calls DROP COLUMN answer_confidence;
ALTER TABLE agent_calls DROP COLUMN answer_label;
ALTER TABLE agent_calls DROP COLUMN operation;
