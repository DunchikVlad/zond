// Аудит-действий поверх Verdict Store (ADR-0013, blueprint п. 14.2): обёртки
// над пакетом internal/audit. Все записи идут через единственное соединение
// store — цепочка хэшей последовательна; прямые INSERT/UPDATE/DELETE из кода
// вне store запрещены конвенцией и триггерами миграции 0004.
package store

import (
	"context"

	"github.com/DunchikVlad/zond/internal/audit"
)

// AppendAudit пишет аудит-события отдельной транзакцией (события жизненного
// цикла скана: start/finish — вне транзакций вердиктов). Ошибка записи
// аудита = ошибка операции (fail-closed: действие без аудита не считается
// совершённым, п. 14.2 «все действия журналируются»).
//
// SIEM-sink (S8-3) не требует пометок при записи: его очередь — сам журнал,
// воркер читает по закладке audit_sink_state (миграция 0009).
func (s *Store) AppendAudit(ctx context.Context, events []audit.Event) error {
	if len(events) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := audit.AppendTx(ctx, tx, events); err != nil {
		return err
	}
	return tx.Commit()
}

// AuditVerify пересчитывает hash-chain аудита (zond audit verify; runbook
// audit-hash-chain-broken.md).
func (s *Store) AuditVerify(ctx context.Context) (*audit.Report, error) {
	return audit.Verify(ctx, s.db)
}

// AuditList — выборка аудита по фильтрам (zond audit export, будущая /audit).
func (s *Store) AuditList(ctx context.Context, f audit.Filter) ([]audit.Entry, error) {
	return audit.List(ctx, s.db, f)
}
