//go:build !windows

// Свободное место на томе через syscall.Statfs (POSIX; blueprint п. 15.3:
// ≥2× размера БД). Windows-вариант — doctor_disk_windows.go (x/sys/windows).

package doctor

import (
	"fmt"
	"syscall"
)

// freeSpace — свободные байты на томе, содержащем path.
func freeSpace(path string) (uint64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, fmt.Errorf("statfs %s: %w", path, err)
	}
	return st.Bavail * uint64(st.Bsize), nil
}
