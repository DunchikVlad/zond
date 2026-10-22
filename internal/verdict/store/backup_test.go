// Тесты онлайн-копии Verdict Store (blueprint п. 15.2): VACUUM INTO,
// отказ от перезаписи, права 0600, восстанавливаемость копии (открытие,
// миграции, данные на месте, hash-chain цел).
package store

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/DunchikVlad/zond/internal/audit"
	"github.com/DunchikVlad/zond/internal/verdict"
)

// TestBackupRoundTrip — копия открывается как store, содержит те же
// данные и проходит верификацию цепочки (учебное восстановление, DoD п. 22).
func TestBackupRoundTrip(t *testing.T) {
	st := openTest(t)
	ctx := context.Background()
	now := time.Now().UTC()

	mustSaveScan(t, st, "s1")
	if err := st.SaveVerdicts(ctx, []verdict.Verdict{{
		ID: "v1", ScanID: "s1", Table: "t", Path: "c1", Label: "EMAIL",
		ReviewStatus: verdict.StatusAutoAccepted, CreatedAt: now,
	}}); err != nil {
		t.Fatalf("SaveVerdicts: %v", err)
	}
	// Аудит-событие — чтобы в копии была непустая цепочка.
	if err := st.AppendAudit(ctx, []audit.Event{{
		Actor: "cli", Category: audit.CatScan, Action: "scan_start",
		Target: "scan:s1", Details: map[string]any{"source": "x"}, TS: now,
	}}); err != nil {
		t.Fatalf("AppendAudit: %v", err)
	}

	out := filepath.Join(t.TempDir(), "copy.db")
	size, err := st.Backup(ctx, out)
	if err != nil {
		t.Fatalf("Backup: %v", err)
	}
	if size <= 0 {
		t.Fatalf("Backup: size=%d", size)
	}
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(out)
		if err != nil {
			t.Fatalf("stat: %v", err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("права копии = %o, ожидалось 0600", fi.Mode().Perm())
		}
	}

	// Восстановление: открываем копию как store.
	restored, err := Open(out)
	if err != nil {
		t.Fatalf("восстановленная копия не открывается: %v", err)
	}
	defer restored.Close()
	ver, err := restored.AuditVerify(ctx)
	if err != nil || !ver.OK() {
		t.Fatalf("цепочка копии: %+v err=%v", ver, err)
	}
	sum, err := restored.VerdictSummary(ctx, "s1")
	if err != nil || sum.Total != 1 {
		t.Fatalf("данные копии: %+v err=%v", sum, err)
	}
}

// TestBackupNoOverwrite — существующий файл не перезаписывается (fail-closed).
func TestBackupNoOverwrite(t *testing.T) {
	st := openTest(t)
	out := filepath.Join(t.TempDir(), "copy.db")
	if err := os.WriteFile(out, []byte("другие данные"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Backup(context.Background(), out); err == nil {
		t.Fatal("перезапись существующего файла должна отклоняться")
	}
	raw, _ := os.ReadFile(out)
	if string(raw) != "другие данные" {
		t.Error("существующий файл изменён")
	}
}

// TestBackupFilename — имя копии по метке времени.
func TestBackupFilename(t *testing.T) {
	now := time.Date(2026, 10, 22, 3, 4, 5, 0, time.UTC)
	if got := BackupFilename(now); got != "zond-20261022-030405.db" {
		t.Errorf("BackupFilename = %q", got)
	}
}

// TestLatestBackupEvents — аудит-записи backup парсятся в BackupEvent
// (источник правила backup_failed, п. 17).
func TestLatestBackupEvents(t *testing.T) {
	st := openTest(t)
	ctx := context.Background()
	now := time.Now().UTC()

	if evs, err := st.LatestBackupEvents(ctx, 5); err != nil || len(evs) != 0 {
		t.Fatalf("пустой журнал: %+v err=%v", evs, err)
	}
	auditBackup := func(status, path, errMsg string, ts time.Time) {
		t.Helper()
		d := map[string]any{"status": status, "path": path}
		if errMsg != "" {
			d["error"] = errMsg
		}
		if err := st.AppendAudit(ctx, []audit.Event{{
			Actor: "scheduler", Category: audit.CatAdmin, Action: "backup",
			Target: "backup:" + path, Details: d, TS: ts,
		}}); err != nil {
			t.Fatalf("AppendAudit: %v", err)
		}
	}
	auditBackup("ok", "/b/1.db", "", now.Add(-2*time.Hour))
	auditBackup("fail", "/b/2.db", "нет места", now.Add(-time.Hour))

	evs, err := st.LatestBackupEvents(ctx, 5)
	if err != nil || len(evs) != 2 {
		t.Fatalf("events: %+v err=%v", evs, err)
	}
	if evs[0].Status != "fail" || evs[0].Error != "нет места" || evs[0].Path != "/b/2.db" {
		t.Errorf("последнее событие: %+v", evs[0])
	}
	if evs[1].Status != "ok" || evs[1].Path != "/b/1.db" {
		t.Errorf("предпоследнее событие: %+v", evs[1])
	}
}
