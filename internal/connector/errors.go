package connector

import (
	"context"
	"errors"
	"net"
	"sync"
)

// FailureReason — классификация причины ошибки источника (blueprint п. 13.2):
// circuit breaker и retry срабатывают только на retryable-ошибки драйвера
// (перегрузка, таймаут, потеря лидерства) — причина source_overload.
type FailureReason string

const (
	// ReasonOther — прочие ошибки: retry не применяется, breaker не считает.
	ReasonOther FailureReason = ""
	// ReasonOverload — перегрузка/таймаут/потеря лидерства: retryable.
	ReasonOverload FailureReason = "source_overload"
)

var (
	classifierMu sync.RWMutex
	classifiers  []func(error) (FailureReason, bool)
)

// RegisterFailureClassifier регистрирует классификатор драйвера (init
// подпакетов clickhouse/mongodb). Первый признавший ошибку выигрывает.
func RegisterFailureClassifier(fn func(error) (FailureReason, bool)) {
	if fn == nil {
		return
	}
	classifierMu.Lock()
	defer classifierMu.Unlock()
	classifiers = append(classifiers, fn)
}

// ClassifyFailure возвращает причину ошибки. Базовые случаи (сеть/контекст)
// разбираются здесь; специфику драйверов добавляют зарегистрированные
// классификаторы. Ошибки отмены (context.Canceled) — не overload: это
// мягкая остановка прогона (п. 11.2 stop), а не болезнь источника.
func ClassifyFailure(err error) FailureReason {
	if err == nil {
		return ReasonOther
	}
	if errors.Is(err, context.Canceled) {
		return ReasonOther
	}
	classifierMu.RLock()
	for _, fn := range classifiers {
		if reason, ok := fn(err); ok {
			classifierMu.RUnlock()
			return reason
		}
	}
	classifierMu.RUnlock()
	if mongoNetworkError(err) {
		return ReasonOverload
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return ReasonOverload
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return ReasonOverload
	}
	return ReasonOther
}

// IsRetryable — retry только на retryable-ошибки (п. 13.2).
func IsRetryable(err error) bool {
	return ClassifyFailure(err) == ReasonOverload
}

// mongoNetworkError — обёртка над mongo.IsNetworkError без жёсткого импорта
// драйвера в базовый пакет: подпакет mongodb регистрирует проверку через
// RegisterNetworkProbe на init.
var mongoNetworkProbe func(error) bool

// RegisterNetworkProbe подключает детектор сетевых ошибок драйвера
// (internal/connector/mongodb, init).
func RegisterNetworkProbe(fn func(error) bool) {
	if fn == nil {
		return
	}
	classifierMu.Lock()
	defer classifierMu.Unlock()
	mongoNetworkProbe = fn
}

func mongoNetworkError(err error) bool {
	classifierMu.RLock()
	fn := mongoNetworkProbe
	classifierMu.RUnlock()
	return fn != nil && fn(err)
}

// String для диагностики.
func (r FailureReason) String() string { return string(r) }
