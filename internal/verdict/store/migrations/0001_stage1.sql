-- +goose Up
-- Stage 1 minimal schema: scans, scan_tables, verdicts.
-- Full schema per blueprint 11.1 arrives at stage 5.

CREATE TABLE scans (
    id          TEXT PRIMARY KEY,
    source_name TEXT NOT NULL,
    profile     TEXT NOT NULL,
    status      TEXT NOT NULL CHECK (status IN
        ('running', 'partial', 'done', 'interrupted', 'failed', 'budget_exceeded')),
    started_at  TEXT NOT NULL,
    finished_at TEXT,
    stats_json  TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE scan_tables (
    scan_id    TEXT NOT NULL REFERENCES scans(id),
    table_name TEXT NOT NULL,
    row_count  INTEGER NOT NULL DEFAULT 0,
    status     TEXT NOT NULL CHECK (status IN ('done', 'failed', 'skipped')),
    error      TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (scan_id, table_name)
);

CREATE TABLE verdicts (
    id               TEXT PRIMARY KEY,
    scan_id          TEXT NOT NULL REFERENCES scans(id),
    table_name       TEXT NOT NULL,
    path             TEXT NOT NULL,
    native_type      TEXT NOT NULL,
    label            TEXT NOT NULL,
    sensitivity      TEXT NOT NULL,
    confidence       REAL NOT NULL CHECK (confidence BETWEEN 0 AND 1),
    evidence_layer   TEXT NOT NULL,
    evidence         TEXT NOT NULL DEFAULT '{}',
    taxonomy_version  TEXT NOT NULL DEFAULT '',
    detectors_version TEXT NOT NULL DEFAULT '',
    prompt_version    TEXT NOT NULL DEFAULT '',
    sample_size      INTEGER NOT NULL DEFAULT 0,
    cluster_id       TEXT NOT NULL DEFAULT '',
    review_status    TEXT NOT NULL CHECK (review_status IN
        ('auto_accepted', 'pending', 'confirmed', 'rejected', 'relabelled')),
    final_label      TEXT NOT NULL DEFAULT '',
    reviewed_by      TEXT NOT NULL DEFAULT '',
    reviewed_at      TEXT NOT NULL DEFAULT '',
    created_at       TEXT NOT NULL
);

CREATE INDEX idx_verdicts_scan   ON verdicts(scan_id);
CREATE INDEX idx_verdicts_review ON verdicts(review_status);
CREATE INDEX idx_verdicts_label  ON verdicts(label);

-- +goose Down
DROP INDEX IF EXISTS idx_verdicts_label;
DROP INDEX IF EXISTS idx_verdicts_review;
DROP INDEX IF EXISTS idx_verdicts_scan;

DROP TABLE IF EXISTS verdicts;
DROP TABLE IF EXISTS scan_tables;
DROP TABLE IF EXISTS scans;
