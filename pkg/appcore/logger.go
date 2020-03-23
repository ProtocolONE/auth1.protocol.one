package appcore

import (
	"os"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func InitLogger() *zap.Logger {
	var logger *zap.Logger
	if _, ok := os.LookupEnv("AUTHONE_LOGGING_DEV"); ok {
		logger = newDevLogger()
	} else {
		logger = newProdLogger()
	}
	zap.ReplaceGlobals(logger)
	return logger
}

func newProdLogger() *zap.Logger {
	return zap.New(
		zapcore.NewCore(
			zapcore.NewJSONEncoder(zapcore.EncoderConfig{
				MessageKey:  "msg",
				LevelKey:    "level",
				TimeKey:     "ts",
				EncodeLevel: zapcore.LowercaseLevelEncoder,
				EncodeTime:  zapcore.ISO8601TimeEncoder,
			}),
			os.Stdout,
			zap.DebugLevel,
		),
	)
}

func newDevLogger() *zap.Logger {
	return zap.New(
		zapcore.NewCore(
			zapcore.NewConsoleEncoder(zapcore.EncoderConfig{
				MessageKey:  "msg",
				LevelKey:    "level",
				TimeKey:     "ts",
				EncodeLevel: zapcore.CapitalColorLevelEncoder,
				EncodeTime:  zapcore.ISO8601TimeEncoder,
			}),
			os.Stdout,
			zap.DebugLevel,
		),
	)
}
