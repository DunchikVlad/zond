-- +goose Up
-- Встроенный алертинг инстанса (blueprint п. 17): журнал алертов.
-- Дедуп по (rule, target): открытый алерт не дублируется — продлевается
-- last_seen_at; закрытие (state='resolved') — когда правило перестаёт
-- стрелять (evaluator, прогон по расписанию scheduler'а).

CREATE TABLE alerts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    rule         TEXT NOT NULL,
    severity     TEXT NOT NULL CHECK (severity IN ('warning', 'critical')),
    target       TEXT NOT NULL,
    message      TEXT NOT NULL,
    details_json TEXT NOT NULL DEFAULT '{}',
    state        TEXT NOT NULL CHECK (state IN ('open', 'resolved')),
    created_at   TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    resolved_at  TEXT NOT NULL DEFAULT ''
);

CREATE INDEX idx_alerts_open ON alerts(rule, target, state);

-- +goose Down
DROP INDEX IF EXISTS idx_alerts_open;

DROP TABLE IF EXISTS alerts;
