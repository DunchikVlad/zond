-- +goose Up
-- SIEM-sink (blueprint п. 14.2, ADR-0013, S8-3): закладка доставки аудит-
-- журнала во внешний sink (syslog/CEF или JSON-over-TCP). Потеря событий
-- недопустима: очередь — сам audit_log (append-only, миграция 0004);
-- воркер (internal/audit/sink.go) доставляет строго в порядке цепочки и
-- двигает закладку last_seq только за доставленное событие. Недоступность
-- sink → закладка не двигается, повторная отправка (backoff воркера).
-- Одна строка на инстанс (single-instance, ADR-0014).

CREATE TABLE audit_sink_state (
    id         INTEGER PRIMARY KEY CHECK (id = 1),
    last_seq   INTEGER NOT NULL DEFAULT 0,  -- последний доставленный seq audit_log
    last_error TEXT NOT NULL DEFAULT '',    -- диагностика последней неудачи
    updated_at TEXT                         -- RFC3339 последнего обновления
);

INSERT INTO audit_sink_state (id) VALUES (1);

-- +goose Down
DROP TABLE IF EXISTS audit_sink_state;
