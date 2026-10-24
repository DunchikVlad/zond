package clickhouse

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/DunchikVlad/zond/internal/connector"
)

func TestClassifyClickHouseCodes(t *testing.T) {
	retryable := []int32{159, 202, 203, 241, 252}
	for _, code := range retryable {
		err := fmt.Errorf("запрос: %w", &clickhouse.Exception{Code: code, Name: ".overload"})
		if got := connector.ClassifyFailure(err); got != connector.ReasonOverload {
			t.Errorf("код %d: %q, ожидалось source_overload", code, got)
		}
		if !connector.IsRetryable(err) {
			t.Errorf("код %d: IsRetryable=false, ожидалось true", code)
		}
	}
	// Не-overload коды (синтаксис/доступ/несуществующая таблица).
	for _, code := range []int32{62, 81, 60} {
		err := &clickhouse.Exception{Code: code}
		if got := connector.ClassifyFailure(err); got != connector.ReasonOther {
			t.Errorf("код %d: %q, ожидалось ''", code, got)
		}
	}
	// Отмена и дедлайн не путаются с кодами драйвера.
	if got := connector.ClassifyFailure(context.Canceled); got != connector.ReasonOther {
		t.Errorf("context.Canceled: %q", got)
	}
	if got := connector.ClassifyFailure(errors.New("unknown")); got != connector.ReasonOther {
		t.Errorf("plain: %q", got)
	}
}
