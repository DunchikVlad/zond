package mongodb

import (
	"context"
	"fmt"
	"testing"

	"github.com/DunchikVlad/zond/internal/connector"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

func TestClassifyMongoCodes(t *testing.T) {
	// Retryable: перегрузка/потеря лидерства (п. 13.2).
	retryable := []int32{91, 189, 10107, 13435, 13436, 11600, 11602}
	for _, code := range retryable {
		var err error = &mongo.CommandError{Code: code, Message: "stepdown"}
		err = fmt.Errorf("find: %w", err)
		if got := connector.ClassifyFailure(err); got != connector.ReasonOverload {
			t.Errorf("код %d: %q, ожидалось source_overload", code, got)
		}
	}
	// Не-retryable коды (валидация документа, duplicate key, unauthorized).
	for _, code := range []int32{11, 11000, 13} {
		err := &mongo.CommandError{Code: code}
		if got := connector.ClassifyFailure(err); got != connector.ReasonOther {
			t.Errorf("код %d: %q, ожидалось ''", code, got)
		}
	}
	if got := connector.ClassifyFailure(context.Canceled); got != connector.ReasonOther {
		t.Errorf("context.Canceled: %q", got)
	}
	if got := connector.ClassifyFailure(context.DeadlineExceeded); got != connector.ReasonOverload {
		t.Errorf("context.DeadlineExceeded: %q, ожидалось source_overload", got)
	}
}
