package api

import (
	"strconv"
	"time"

	"github.com/ProtocolONE/auth1.protocol.one/pkg/appcore/log"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func RequestLogger(skipper func(echo.Context) bool) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			start := time.Now()

			err := next(c)

			if skipper(c) {
				return err
			}

			duration := time.Since(start)
			req := c.Request()
			res := c.Response()

			p := req.URL.Path
			if p == "" {
				p = "/"
			}

			var bytesIn int64 = 0
			if v, err := strconv.ParseInt(req.Header.Get(echo.HeaderContentLength), 10, 64); err == nil {
				bytesIn = v
			}

			status := res.Status
			fields := []zapcore.Field{
				zap.Int("status", status),
				zap.String("method", req.Method),
				zap.String("uri", req.RequestURI),
				zap.String("host", req.Host),
				zap.String("path", p),
				zap.String("remote_ip", c.RealIP()),
				zap.String("referer", req.Referer()),
				zap.String("user_agent", req.UserAgent()),
				// zap.String("time_unix", strconv.FormatInt(time.Now().Unix(), 10)),
				// zap.String("time_unix_nano", strconv.FormatInt(time.Now().UnixNano(), 10)),
				// zap.String("time_rfc3339", time.Now().Format(time.RFC3339)),
				// zap.String("time_rfc3339_nano", time.Now().Format(time.RFC3339Nano)),
				zap.Int64("latency", int64(duration)),
				zap.String("latency_human", duration.String()),
				zap.Int64("bytes_in", bytesIn),
				zap.Int64("bytes_out", res.Size),
			}

			switch {
			case status >= 500:
				log.Error(c.Request().Context(), "Server error", fields...)
			case status >= 400:
				log.Warn(c.Request().Context(), "Client error", fields...)
			case status >= 300:
				log.Info(c.Request().Context(), "Redirection", fields...)
			default:
				log.Info(c.Request().Context(), "Success", fields...)
			}

			return err
		}
	}
}
