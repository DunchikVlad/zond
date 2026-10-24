package mongodb

import (
	"errors"

	"github.com/DunchikVlad/zond/internal/connector"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

// Коды ошибок MongoDB, трактуемые как перегрузка/потеря лидерства
// (blueprint п. 13.2: retry только на retryable-ошибки драйвера).
var retryableCodes = map[int32]bool{
	91:    true, // ShutdownInProgress
	189:   true, // PrimarySteppedDown
	10107: true, // NotWritablePrimary
	13435: true, // NotPrimaryNoSecondaryOk
	13436: true, // NotPrimaryOrSecondary
	11600: true, // InterruptedAtShutdown
	11602: true, // InterruptedDueToReplStateChange
}

func init() {
	connector.RegisterNetworkProbe(mongo.IsNetworkError)
	connector.RegisterFailureClassifier(func(err error) (connector.FailureReason, bool) {
		var ce *mongo.CommandError
		if errors.As(err, &ce) && retryableCodes[ce.Code] {
			return connector.ReasonOverload, true
		}
		return connector.ReasonOther, false
	})
}
