package postgres

import (
	"errors"
	"strings"

	"github.com/DunchikVlad/zond/internal/connector"
	"github.com/lib/pq"
)

// Коды ошибок PostgreSQL, трактуемые как перегрузка/временная недоступность
// (blueprint п. 13.2: retry только на retryable-ошибки драйвера).
var retryableCodes = map[string]bool{
	"53300": true, // too_many_connections
	"53400": true, // configuration_limit_exceeded
	"57P01": true, // admin_shutdown
	"57P02": true, // crash_shutdown
	"57P03": true, // cannot_connect_now
	"58030": true, // io_error
}

func init() {
	connector.RegisterFailureClassifier(func(err error) (connector.FailureReason, bool) {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && retryableCodes[string(pqErr.Code)] {
			return connector.ReasonOverload, true
		}
		// connection reset / broken pipe / network — тоже overload
		if err != nil && (strings.Contains(err.Error(), "connection reset") ||
			strings.Contains(err.Error(), "broken pipe") ||
			strings.Contains(err.Error(), "connection refused")) {
			return connector.ReasonOverload, true
		}
		return connector.ReasonOther, false
	})
}
