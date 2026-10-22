// Онлайн-резервное копирование Verdict Store (blueprint п. 15.2):
// согласованный снимок через VACUUM INTO без остановки сервиса.
// Шифрование копии — на уровне ФС/диска (п. 14), хранение вне инстанса
// (S3/WORM) — ответственность оператора.
package store

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

// Backup создаёт онлайн-копию БД в outPath (VACUUM INTO, п. 15.2).
// Fail-closed: существующий файл не перезаписывается; после копии права
// 0600 (копия содержит данные инстанса — только владелец). Возвращает
// размер созданной копии.
func (s *Store) Backup(ctx context.Context, outPath string) (int64, error) {
	if outPath == "" {
		return 0, errors.New("backup: путь назначения обязателен")
	}
	if _, err := os.Stat(outPath); err == nil {
		return 0, fmt.Errorf("backup: %s уже существует — перезапись копий запрещена", outPath)
	}
	// VACUUM INTO не параметризуется — экранируем кавычки пути.
	if strings.ContainsAny(outPath, "\x00") {
		return 0, errors.New("backup: недопустимый символ в пути")
	}
	escaped := strings.ReplaceAll(outPath, "'", "''")
	if _, err := s.db.ExecContext(ctx, `VACUUM INTO '`+escaped+`'`); err != nil {
		return 0, fmt.Errorf("backup: VACUUM INTO: %w", err)
	}
	if err := os.Chmod(outPath, 0o600); err != nil {
		return 0, fmt.Errorf("backup: chmod 0600: %w", err)
	}
	fi, err := os.Stat(outPath)
	if err != nil {
		return 0, fmt.Errorf("backup: stat результата: %w", err)
	}
	return fi.Size(), nil
}

// BackupFilename — имя файла копии по метке времени: zond-YYYYMMDD-HHMMSS.db
// (локальное время инстанса; секундная точность достаточна для расписания).
func BackupFilename(now time.Time) string {
	return "zond-" + now.Format("20060102-150405") + ".db"
}
