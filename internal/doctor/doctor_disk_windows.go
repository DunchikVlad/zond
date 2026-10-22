//go:build windows

// Свободное место на томе через GetDiskFreeSpaceExW (blueprint п. 15.3:
// ≥2× размера БД). POSIX-вариант — doctor_disk_unix.go (syscall.Statfs).

package doctor

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	kernel32               = syscall.NewLazyDLL("kernel32.dll")
	getDiskFreeSpaceExProc = kernel32.NewProc("GetDiskFreeSpaceExW")
)

// freeSpace — свободные байты на томе, содержащем path.
func freeSpace(path string) (uint64, error) {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0, fmt.Errorf("путь %s: %w", path, err)
	}
	var freeBytes int64
	// GetDiskFreeSpaceExW(directoryName, freeBytesAvailable, totalNumberOfBytes,
	// totalNumberOfFreeBytes); nil — нас интересует только freeBytes.
	r1, _, err := getDiskFreeSpaceExProc.Call(
		uintptr(unsafe.Pointer(p)),
		uintptr(unsafe.Pointer(&freeBytes)),
		0, 0)
	if r1 == 0 {
		if err != windows.ERROR_SUCCESS {
			return 0, fmt.Errorf("GetDiskFreeSpaceEx %s: %w", path, err)
		}
		return 0, fmt.Errorf("GetDiskFreeSpaceEx %s: неизвестная ошибка", path)
	}
	if freeBytes < 0 {
		return 0, fmt.Errorf("GetDiskFreeSpaceEx %s: отрицательное значение", path)
	}
	return uint64(freeBytes), nil
}
