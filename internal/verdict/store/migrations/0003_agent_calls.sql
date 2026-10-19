-- +goose Up
-- Учёт LLM-вызовов (blueprint п. 10.6, п. 11.1) и прайс-лист моделей.
-- Атомарность п. 13: строка agent_calls пишется в одной транзакции с вердиктом
-- (SaveVerdictsWithCalls) — либо agent_calls+verdicts, либо откат.

CREATE TABLE agent_calls (
    id             TEXT PRIMARY KEY,
    scan_id        TEXT NOT NULL REFERENCES scans(id),
    verdict_id     TEXT NOT NULL REFERENCES verdicts(id),
    agent_id       TEXT NOT NULL,
    model          TEXT NOT NULL,
    prompt_version TEXT NOT NULL DEFAULT '',
    tokens_in      INTEGER NOT NULL DEFAULT 0,
    tokens_out     INTEGER NOT NULL DEFAULT 0,
    cost_usd       REAL NOT NULL DEFAULT 0,
    latency_ms     INTEGER NOT NULL DEFAULT 0,
    cached         INTEGER NOT NULL DEFAULT 0,
    status         TEXT NOT NULL CHECK (status IN ('ok', 'error', 'cache_hit')),
    created_at     TEXT NOT NULL
);

CREATE INDEX idx_agent_calls_scan ON agent_calls(scan_id);

-- Прайс-лист: стоимость за 1M токенов (in/out), действует с effective_from.
-- Цены OpenAI (list) на момент инкремента; сверка фактической экономики — п. 17.
CREATE TABLE model_prices (
    model          TEXT NOT NULL,
    per_1m_in      REAL NOT NULL,
    per_1m_out     REAL NOT NULL,
    effective_from TEXT NOT NULL,
    PRIMARY KEY (model, effective_from)
);

INSERT OR IGNORE INTO model_prices (model, per_1m_in, per_1m_out, effective_from) VALUES
    ('gpt-4o-mini', 0.15, 0.60, '2026-01-01'),
    ('gpt-4o',      2.50, 10.00, '2026-01-01');

-- +goose Down
DROP INDEX IF EXISTS idx_agent_calls_scan;

DROP TABLE IF EXISTS agent_calls;
DROP TABLE IF EXISTS model_prices;
