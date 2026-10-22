// Онлайн-резервное копирование Verdict Store (blueprint п. 15.2):
// согласованный снимок через VACUUM INTO без остановки сервиса.
// Шифрование копии — на уровне ФС/диска (п. 14), хранение вне инстанса
// (S3/WORM) — ответственность оператора.
package store

import (
	"context"
	"encoding/json"
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

// BackupEvent — аудит-запись о попытке копии (п. 14.2, п. 15.2): источник
// данных для правила алертинга backup_failed (п. 17).
type BackupEvent struct {
	Seq    int64
	Status string // ok | fail
	Path   string
	Error  string
	TS     time.Time
}

// LatestBackupEvents — последние записи backup из аудит-лога (свежие первыми).
func (s *Store) LatestBackupEvents(ctx context.Context, limit int) ([]BackupEvent, error) {
	if limit <= 0 {
		limit = 10
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT seq, ts, details_json FROM audit_log
		WHERE category = 'admin' AND action = 'backup'
		ORDER BY seq DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []BackupEvent
	for rows.Next() {
		var ev BackupEvent
		var ts, dj string
		if err := rows.Scan(&ev.Seq, &ts, &dj); err != nil {
			return nil, err
		}
		ev.TS, _ = time.Parse(time.RFC3339, ts)
		var d struct {
			Status string `json:"status"`
			Path   string `json:"path"`
			Error  string `json:"error"`
		}
		_ = json.Unmarshal([]byte(dj), &d)
		ev.Status, ev.Path, ev.Error = d.Status, d.Path, d.Error
		out = append(out, ev)
	}
	return out, rows.Err()
}
