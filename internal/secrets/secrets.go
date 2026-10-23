// Package secrets — резолвер секретов подключений (ADR-0012, blueprint
// п. 12.1): интерфейс Resolver и реализация поверх HashiCorp Vault
// (kv-v2 и dynamic leases через hashicorp/vault/api). Секрет читается в
// момент установки коннекта и живёт только в памяти процесса: на диск, в
// конфиг и в логи не попадает (redact, п. 14.1). Без vault.enabled
// действует прежний режим ${ENV}-интерполяции (internal/config).
package secrets

import (
	"context"
	"errors"
)

// Resolver — источник DSN/URI для источников с ref (ADR-0012).
// Реализация для Vault — Vault (конструктор NewVault/NewFromConfig).
type Resolver interface {
	// Resolve возвращает DSN/URI для ref (имя записи vault.secrets,
	// совпадает с name источника). Ошибка, удовлетворяющая
	// errors.Is(err, ErrUnavailable), означает недоступность Vault без
	// валидного кэша: источник помечается failed с причиной
	// vault_unavailable, остальные источники сканируются (п. 12.1, R11).
	Resolve(ctx context.Context, ref string) (string, error)
	// Close останавливает фоновое продление лиз. Idempotent.
	Close() error
}

// ErrUnavailable — Vault недоступен и нет валидного кэша лизы.
// Ошибки Resolve при сбоях чтения всегда оборачивают этот сентинел.
var ErrUnavailable = errors.New("vault недоступен")

// Действия аудита (п. 14.2: факт резолва/ротации — без значений секрета).
const (
	ActionResolve     = "resolve"       // секрет прочитан из Vault
	ActionRenew       = "lease_renew"   // лиза продлена фоновой горутиной
	ActionRevoked     = "lease_revoked" // лиза отозвана (403) — кэш сброшен
	ActionRenewFailed = "renew_failed"  // продление не удалось; кэш до истечения
)

// AuditHook — факт резолва/ротации секрета без значений (п. 14.2).
// Вызывающий код сам назначает actor аудит-события: инициатор скана для
// ActionResolve (через свой контекст), "scheduler" для фонового продления.
// Nil — без аудита (например, doctor: read-only preflight, п. 15.3).
type AuditHook func(ctx context.Context, ref, path, action string)
