-- +goose Up
-- S9-3: пользовательский промпт на скан. Provenance воспроизводимости:
-- версия базового промпта, хэш и исходный текст пользовательской инструкции
-- (нужен resume: продолжение повторяет промпт исходного прогона) + факт
-- включения LLM-слоя (per-scan override глобального serve -llm).
-- Старые строкы остаются с пустыми значениями — это «неизвестно» и для
-- resume несовместимо (fail-closed), а не разрешение.

ALTER TABLE scans ADD COLUMN prompt_base_version TEXT NOT NULL DEFAULT '';
ALTER TABLE scans ADD COLUMN prompt_hash TEXT NOT NULL DEFAULT '';
ALTER TABLE scans ADD COLUMN prompt_text TEXT NOT NULL DEFAULT '';
ALTER TABLE scans ADD COLUMN llm_enabled INTEGER NOT NULL DEFAULT 0;

-- +goose Down
ALTER TABLE scans DROP COLUMN llm_enabled;
ALTER TABLE scans DROP COLUMN prompt_text;
ALTER TABLE scans DROP COLUMN prompt_hash;
ALTER TABLE scans DROP COLUMN prompt_base_version;
