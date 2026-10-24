package clickhouse

import (
	"errors"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/DunchikVlad/zond/internal/connector"
)

// Коды ошибок ClickHouse, трактуемые как перегрузка/временная недоступность
// (blueprint п. 13.2: retry только на retryable-ошибки драйвера).
var retryableCodes = map[int32]bool{
	159: true, // TIMEOUT_EXCEEDED
	202: true, // TOO_MANY_SIMULTANEOUS_QUERIES
	203: true, // NO_FREE_CONNECTION
	241: true, // MEMORY_LIMIT_EXCEEDED
	252: true, // TOO_MANY_PARTS
}

func init() {
	connector.RegisterFailureClassifier(func(err error) (connector.FailureReason, bool) {
		var ex *clickhouse.Exception
		if errors.As(err, &ex) && retryableCodes[ex.Code] {
			return connector.ReasonOverload, true
		}
		return connector.ReasonOther, false
	})
}
