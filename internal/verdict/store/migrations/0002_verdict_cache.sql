-- +goose Up
-- Кэш вердиктов LLM (blueprint п. 10.5, п. 11.1): ключ — sha256 составной
-- (agent|model|prompt|taxonomy|mask_profile|fingerprint(values)); TTL 30 дней,
-- прочистка — фоновая задача шедулера (п. 15.4).

CREATE TABLE verdict_cache (
    cache_key    TEXT PRIMARY KEY,
    agent_id     TEXT NOT NULL,
    verdict_json TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    expires_at   TEXT NOT NULL
);

CREATE INDEX idx_verdict_cache_expires ON verdict_cache(expires_at);

-- +goose Down
DROP INDEX IF EXISTS idx_verdict_cache_expires;
DROP TABLE IF EXISTS verdict_cache;
