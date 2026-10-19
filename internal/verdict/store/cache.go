package store

import (
	"context"
	"database/sql"
	"time"
)

// CacheTTLDefault — TTL записи кэша вердиктов по умолчанию (blueprint п. 10.5:
// default 30 дней).
const CacheTTLDefault = 30 * 24 * time.Hour

// CachedVerdict — запись кэша вердиктов LLM (blueprint п. 10.5).
type CachedVerdict struct {
	AgentID     string
	VerdictJSON string // {"label": "...", "confidence": 0.0} — без сырых значений
	CreatedAt   time.Time
	ExpiresAt   time.Time
}

// CacheGet возвращает непросроченную запись кэша по ключу.
func (s *Store) CacheGet(ctx context.Context, key string, now time.Time) (*CachedVerdict, bool, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT agent_id, verdict_json, created_at, expires_at
		 FROM verdict_cache WHERE cache_key = ? AND expires_at > ?`,
		key, now.UTC().Format(time.RFC3339))
	var cv CachedVerdict
	var created, expires string
	err := row.Scan(&cv.AgentID, &cv.VerdictJSON, &created, &expires)
	if err == sql.ErrNoRows {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	cv.CreatedAt, _ = time.Parse(time.RFC3339, created)
	cv.ExpiresAt, _ = time.Parse(time.RFC3339, expires)
	return &cv, true, nil
}

// CachePut сохраняет (или заменяет) запись кэша.
func (s *Store) CachePut(ctx context.Context, key string, cv CachedVerdict) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO verdict_cache (cache_key, agent_id, verdict_json, created_at, expires_at)
		 VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT (cache_key) DO UPDATE SET
		   agent_id = excluded.agent_id, verdict_json = excluded.verdict_json,
		   created_at = excluded.created_at, expires_at = excluded.expires_at`,
		key, cv.AgentID, cv.VerdictJSON,
		cv.CreatedAt.UTC().Format(time.RFC3339), cv.ExpiresAt.UTC().Format(time.RFC3339))
	return err
}

// CachePurgeExpired удаляет просроченные записи; возвращает число удалённых
// (blueprint п. 15.4 — фоновая прочистка шедулером).
func (s *Store) CachePurgeExpired(ctx context.Context, now time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM verdict_cache WHERE expires_at <= ?`, now.UTC().Format(time.RFC3339))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
