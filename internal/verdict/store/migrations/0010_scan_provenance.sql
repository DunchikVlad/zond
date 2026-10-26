-- +goose Up
-- S9-1: qualified table identity для новых прогонов и fail-closed provenance
-- для resume. Старые строки сохраняются без выдумывания неизвестной схемы.
ALTER TABLE scans ADD COLUMN table_identity_version INTEGER NOT NULL DEFAULT 1;
ALTER TABLE scans ADD COLUMN config_fingerprint TEXT NOT NULL DEFAULT '';
ALTER TABLE scans ADD COLUMN taxonomy_version TEXT NOT NULL DEFAULT '';
ALTER TABLE scans ADD COLUMN detectors_version TEXT NOT NULL DEFAULT '';
ALTER TABLE scans ADD COLUMN binary_version TEXT NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE scans DROP COLUMN binary_version;
ALTER TABLE scans DROP COLUMN detectors_version;
ALTER TABLE scans DROP COLUMN taxonomy_version;
ALTER TABLE scans DROP COLUMN config_fingerprint;
ALTER TABLE scans DROP COLUMN table_identity_version;
