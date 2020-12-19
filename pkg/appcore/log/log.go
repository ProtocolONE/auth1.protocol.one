package log

import (
	"context"

	"github.com/ProtocolONE/auth1.protocol.one/pkg/appcore"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Logger returns the logger associated with the given context. If there is no logger, it will return global one.
func Logger(ctx context.Context) *zap.Logger {
	if ctx == nil {
		panic("nil context passed to Logger")
	}
	appctx := appcore.Context(ctx)
	return appctx.Logger
}

// Debug calls Logger(ctx).Debug(msg, fields...).
func Debug(ctx context.Context, msg string, fields ...zapcore.Field) {
	Logger(ctx).Debug(msg, fields...)
}

// Info calls Logger(ctx).Info(msg, fields...).
func Info(ctx context.Context, msg string, fields ...zapcore.Field) {
	Logger(ctx).Info(msg, fields...)
}

// Warn calls Logger(ctx).Warn(msg, fields...).
func Warn(ctx context.Context, msg string, fields ...zapcore.Field) {
	Logger(ctx).Warn(msg, fields...)
}

// Error calls Logger(ctx).Error(msg, fields...).
func Error(ctx context.Context, msg string, fields ...zapcore.Field) {
	Logger(ctx).Error(msg, fields...)
}
