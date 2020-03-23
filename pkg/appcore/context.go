package appcore

import (
	"context"

	"go.uber.org/zap"
)

type Ctx struct {
	RequestID string
	DeviceID  string
	// Challenge string // todo Session identifier
	Logger *zap.Logger
}

// contextKey holds the context key used for app context.
type contextKey struct{}

func With(ctx context.Context, appctx Ctx) context.Context {
	return context.WithValue(ctx, contextKey{}, appctx)
}

func Context(ctx context.Context) Ctx {
	if ctx == nil {
		panic("nil context passed to Context")
	}
	if appctx, ok := ctx.Value(contextKey{}).(Ctx); ok {
		return appctx
	}
	return Ctx{Logger: zap.L()}
}

func WithRequest(ctx context.Context, requestID, deviceID string) context.Context { // todo add session id
	return With(ctx, Ctx{
		RequestID: requestID,
		Logger:    zap.L().With(zap.String("request_id", requestID), zap.String("device_id", deviceID)),
	})
}
