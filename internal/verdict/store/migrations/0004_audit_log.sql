-- +goose Up
-- Security audit log (blueprint п. 14.2, ADR-0013): append-only журнал всех
-- действий (UI/API/CLI/агенты) с цепочкой хэшей против подмены/удаления.
-- Запись — только INSERT (код + триггеры); hash-chain считается в той же
-- транзакции, что и INSERT (canonical form — пакет internal/audit).
-- Внешний sink в SIEM, retention и страница /audit — этапы 5b+/UI (п. 14.2).

CREATE TABLE audit_log (
    seq          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts           TEXT NOT NULL,
    actor        TEXT NOT NULL,
    category     TEXT NOT NULL,
    action       TEXT NOT NULL,
    target       TEXT NOT NULL DEFAULT '',
    details_json TEXT NOT NULL DEFAULT '{}',
    prev_hash    TEXT NOT NULL,
    entry_hash   TEXT NOT NULL
);

CREATE INDEX idx_audit_ts    ON audit_log(ts);
CREATE INDEX idx_audit_actor ON audit_log(actor);

-- Append-only: UPDATE/DELETE запрещены на уровне БД (п. 14.2). Код пакета
-- internal/audit экспонирует только вставку; триггеры — защита в глубину
-- (прямой доступ к БД, компрометация приложения с правами на файл).
-- goose делит миграцию по ';' — тело триггера обёрнуто в StatementBegin/End.
-- +goose StatementBegin
CREATE TRIGGER audit_log_no_update BEFORE UPDATE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only (ADR-0013, blueprint п. 14.2)');
END;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TRIGGER audit_log_no_delete BEFORE DELETE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only (ADR-0013, blueprint п. 14.2)');
END;
-- +goose StatementEnd

-- +goose Down
DROP TRIGGER IF EXISTS audit_log_no_delete;
DROP TRIGGER IF EXISTS audit_log_no_update;

DROP INDEX IF EXISTS idx_audit_actor;
DROP INDEX IF EXISTS idx_audit_ts;

DROP TABLE IF EXISTS audit_log;
