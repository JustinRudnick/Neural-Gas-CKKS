package util

import (
	"errors"
	"fmt"
	"log/slog"
)

// writes message to logger (iff not nil) and panics, if err != nil
// panics with error: "prefix <err>" if errorPrefix is set
func Panic(err error, logger *slog.Logger, logMsg string, errorPrefix ...string) {
	if err != nil {
		if logger != nil {
			logger.Error(logMsg)
		}
		newErr := err.Error()
		for _, s := range errorPrefix {
			newErr = fmt.Sprintf("%s %s", s, newErr)
		}
		panic(errors.New(newErr))
	}
}

func Assure(pass func() bool, logger *slog.Logger, logMsg string, panicMsg string) {
	if !pass() {
		if logger != nil {
			logger.Error(logMsg)
		}
		panic(errors.New(panicMsg))
	}
}
