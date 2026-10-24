-- +goose Up
-- Причина failed-таблицы (blueprint п. 13.2): circuit breaker считает только
-- 'source_overload'. Добавляется добавляющей миграцией (конвенция п. 4).

ALTER TABLE scan_tables ADD COLUMN reason TEXT NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE scan_tables DROP COLUMN reason;
