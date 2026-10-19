-- +goose Up
-- Пользователи SSO (JIT-прvisioning, ADR-0011, blueprint п. 11.1) и
-- API-токены программного доступа (п. 14.2). api_tokens хранит только
-- хэш ключа — сам ключ показывается один раз при выпуске (формат хэша —
-- ADR-impl-5в).

CREATE TABLE users (
    subject       TEXT PRIMARY KEY,        -- SAML NameID (п. 11.3)
    display_name  TEXT NOT NULL DEFAULT '',
    role          TEXT NOT NULL CHECK (role IN ('admin', 'viewer')),
    last_login_at TEXT NOT NULL DEFAULT '',
    created_at    TEXT NOT NULL DEFAULT ''
);

-- API-токены (п. 14.2): scope read|review|export|admin через запятую
-- (RBAC-матрица п. 11.3 расширена scope'ами программного доступа).
-- key_hash — хэш ключа; сам ключ показывается один раз при выпуске.
CREATE TABLE api_tokens (
    id           TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    scopes       TEXT NOT NULL,            -- CSV: read,review,export,admin
    key_hash     TEXT NOT NULL UNIQUE,
    issued_by    TEXT NOT NULL,            -- sso:<subject> | token:<id> | cli
    created_at   TEXT NOT NULL,
    expires_at   TEXT NOT NULL,            -- default +90 дней (п. 14.2)
    revoked_at   TEXT NOT NULL DEFAULT '', -- мгновенный отзыв (п. 14.2)
    last_used_at TEXT NOT NULL DEFAULT ''  -- обновляется не чаще раза в час
);

CREATE INDEX idx_api_tokens_hash ON api_tokens(key_hash);

-- +goose Down
DROP INDEX IF EXISTS idx_api_tokens_hash;

DROP TABLE IF EXISTS api_tokens;
DROP TABLE IF EXISTS users;
