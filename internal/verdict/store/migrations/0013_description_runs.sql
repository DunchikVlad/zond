-- +goose Up
-- S9-4: отдельный агентский прогон описания БД (DescriptionRunner).
-- Каждая строка — одна генерация описания по scan_id: статус, промпт,
-- агент/модель, экономика (токены/стоимость/латентность), результат JSON,
-- ошибка, временные метки. История хранится вместе со сканом (retention).
-- FK на scans обеспечивает целостность; scan_id NOT NULL.

CREATE TABLE description_runs (
    id              TEXT PRIMARY KEY,
    scan_id         TEXT NOT NULL REFERENCES scans(id),
    status          TEXT NOT NULL CHECK (status IN ('running','done','failed','interrupted')),
    prompt_version  TEXT NOT NULL DEFAULT '',
    prompt_hash     TEXT NOT NULL DEFAULT '',
    agent_id        TEXT NOT NULL DEFAULT '',
    model           TEXT NOT NULL DEFAULT '',
    tokens_in       INTEGER NOT NULL DEFAULT 0,
    tokens_out      INTEGER NOT NULL DEFAULT 0,
    cost_usd        REAL NOT NULL DEFAULT 0,
    latency_ms      INTEGER NOT NULL DEFAULT 0,
    result_json     TEXT NOT NULL DEFAULT '',
    error           TEXT NOT NULL DEFAULT '',
    created_at      TEXT NOT NULL,
    finished_at     TEXT
);

CREATE INDEX idx_description_runs_scan ON description_runs(scan_id);
CREATE INDEX idx_description_runs_status ON description_runs(status);

-- +goose Down
DROP INDEX IF EXISTS idx_description_runs_status;
DROP INDEX IF EXISTS idx_description_runs_scan;
DROP TABLE IF EXISTS description_runs;
