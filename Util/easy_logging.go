package util

import "log/slog"

// logs an info iff logger is not nil
func LogInfo(logger *slog.Logger, msg string) {
	IfLogged(logger, func() { logger.Info(msg) })
}

// logs an error iff logger is not nil
func LogError(logger *slog.Logger, msg string) {
	IfLogged(logger, func() { logger.Error(msg) })
}

// executes fnc iff logger is not nil
func IfLogged(logger *slog.Logger, fnc func()) {
	if logger != nil {
		fnc()
	}
}
