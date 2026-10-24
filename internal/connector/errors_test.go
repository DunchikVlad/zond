package connector

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
)

type timeoutNetError struct{}

func (timeoutNetError) Error() string   { return "i/o timeout" }
func (timeoutNetError) Timeout() bool   { return true }
func (timeoutNetError) Temporary() bool { return true }

var _ net.Error = timeoutNetError{}

func TestClassifyFailureBase(t *testing.T) {
	// Классификаторы драйверов не зарегистрированы в этом пакете:
	// проверяем базовые случаи (контекст/сеть) и отсутствие паник на nil.
	cases := []struct {
		name string
		err  error
		want FailureReason
	}{
		{"nil", nil, ReasonOther},
		{"отмена", context.Canceled, ReasonOther},
		{"дедлайн", context.DeadlineExceeded, ReasonOverload},
		{"обёрнутый дедлайн", fmt.Errorf("list tables: %w", context.DeadlineExceeded), ReasonOverload},
		{"net timeout", timeoutNetError{}, ReasonOverload},
		{"plain", errors.New("syntax error"), ReasonOther},
	}
	for _, tc := range cases {
		if got := ClassifyFailure(tc.err); got != tc.want {
			t.Errorf("%s: ClassifyFailure = %q, ожидалось %q", tc.name, got, tc.want)
		}
	}
	if !IsRetryable(context.DeadlineExceeded) || IsRetryable(context.Canceled) {
		t.Error("IsRetryable: дедлайн retryable, отмена — нет")
	}
}

func TestClassifyFailureRegistry(t *testing.T) {
	// Первый признавший выигрывает; классификатор, вернувший ok=false,
	// передаёт ошибку дальше.
	RegisterFailureClassifier(func(err error) (FailureReason, bool) {
		if errors.Is(err, errSpecial) {
			return ReasonOverload, true
		}
		return ReasonOther, false
	})
	t.Cleanup(func() {
		classifierMu.Lock()
		classifiers = nil
		classifierMu.Unlock()
	})
	if got := ClassifyFailure(errSpecial); got != ReasonOverload {
		t.Errorf("специальная ошибка: %q, ожидалось overload", got)
	}
	if got := ClassifyFailure(errors.New("прочая")); got != ReasonOther {
		t.Errorf("прочая ошибка: %q, ожидалось ''", got)
	}
}

var errSpecial = errors.New("special driver error")

func TestFailureReasonString(t *testing.T) {
	if ReasonOverload.String() != "source_overload" || ReasonOther.String() != "" {
		t.Error("строковые значения причин изменились (контракт scan_tables.reason)")
	}
}
