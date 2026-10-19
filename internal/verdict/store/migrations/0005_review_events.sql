-- +goose Up
-- Ручное ревью вердиктов (blueprint п. 11.1, п. 11.2 POST /verdicts/{id}/review):
-- append-only журнал действий ревью (confirm/reject/relabel) — петля обратной
-- связи ансамбля (п. 11.3; авто-подстройка порогов — v2). Атомарность п. 13/14.2:
-- смена review_status вердикта + строка review_events + аудит пишутся одной
-- транзакцией (store.ApplyReview).

CREATE TABLE review_events (
    id         TEXT PRIMARY KEY,
    verdict_id TEXT NOT NULL REFERENCES verdicts(id),
    action     TEXT NOT NULL CHECK (action IN ('confirm', 'reject', 'relabel')),
    from_label TEXT NOT NULL,
    to_label   TEXT NOT NULL DEFAULT '',
    actor      TEXT NOT NULL,
    ts         TEXT NOT NULL
);

CREATE INDEX idx_review_events_verdict ON review_events(verdict_id);

-- Append-only, как audit_log: история ревью не переписывается (п. 11.1).
-- +goose StatementBegin
CREATE TRIGGER review_events_no_update BEFORE UPDATE ON review_events
BEGIN
    SELECT RAISE(ABORT, 'review_events is append-only (blueprint п. 11.1)');
END;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TRIGGER review_events_no_delete BEFORE DELETE ON review_events
BEGIN
    SELECT RAISE(ABORT, 'review_events is append-only (blueprint п. 11.1)');
END;
-- +goose StatementEnd

-- +goose Down
DROP TRIGGER IF EXISTS review_events_no_delete;
DROP TRIGGER IF EXISTS review_events_no_update;

DROP INDEX IF EXISTS idx_review_events_verdict;

DROP TABLE IF EXISTS review_events;
