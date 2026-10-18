package connector

import (
	"fmt"
	"sort"
	"sync"
)

// Factory — конструктор коннектора по DSN/URI источника.
// Секреты приходят уже разрешёнными (internal/secrets, ADR-0012).
type Factory func(dsn string) (Connector, error)

var (
	mu        sync.RWMutex
	factories = make(map[string]Factory)
)

// Register регистрирует коннектор типа dbType. Дубль имени — ошибка.
func Register(dbType string, f Factory) error {
	if dbType == "" {
		return fmt.Errorf("connector: пустой тип БД")
	}
	if f == nil {
		return fmt.Errorf("connector: nil factory для %q", dbType)
	}
	mu.Lock()
	defer mu.Unlock()
	if _, ok := factories[dbType]; ok {
		return fmt.Errorf("connector: тип %q уже зарегистрирован", dbType)
	}
	factories[dbType] = f
	return nil
}

// Lookup возвращает конструктор зарегистрированного типа.
func Lookup(dbType string) (Factory, bool) {
	mu.RLock()
	defer mu.RUnlock()
	f, ok := factories[dbType]
	return f, ok
}

// Types — отсортированный список зарегистрированных типов (диагностика, аудит).
func Types() []string {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]string, 0, len(factories))
	for k := range factories {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
