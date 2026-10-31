package postgres

import (
	"context"
	"errors"
	"testing"

	"github.com/DunchikVlad/zond/internal/connector"
	"github.com/lib/pq"
)

func TestClassifyFailure(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want connector.FailureReason
	}{
		{"nil", nil, connector.ReasonOther},
		{"context.Canceled", context.Canceled, connector.ReasonOther},
		{"pq too_many_connections", &pq.Error{Code: "53300"}, connector.ReasonOverload},
		{"pq admin_shutdown", &pq.Error{Code: "57P01"}, connector.ReasonOverload},
		{"pq other", &pq.Error{Code: "42P01"}, connector.ReasonOther},
		{"connection reset", errors.New("connection reset by peer"), connector.ReasonOverload},
		{"other error", errors.New("syntax error"), connector.ReasonOther},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := connector.ClassifyFailure(tt.err)
			if got != tt.want {
				t.Errorf("ClassifyFailure(%v) = %q, want %q", tt.err, got, tt.want)
			}
		})
	}
}
