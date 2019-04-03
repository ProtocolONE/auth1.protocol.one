package api

import (
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"strconv"
	"time"
)

func ZapLogger(log *zap.Logger) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			start := time.Now()

			err := next(c)
			if err != nil {
				c.Error(err)
			}

			stop := time.Now()

			req := c.Request()
			res := c.Response()

			id := req.Header.Get(echo.HeaderXRequestID)
			if id == "" {
				id = res.Header().Get(echo.HeaderXRequestID)
			}

			p := req.URL.Path
			if p == "" {
				p = "/"
			}

			cl := req.Header.Get(echo.HeaderContentLength)
			if cl == "" {
				cl = "0"
			}

			fields := []zapcore.Field{
				zap.String("time_unix", strconv.FormatInt(time.Now().Unix(), 10)),
				zap.String("time_unix_nano", strconv.FormatInt(time.Now().UnixNano(), 10)),
				zap.String("time_rfc3339", time.Now().Format(time.RFC3339)),
				zap.String("time_rfc3339_nano", time.Now().Format(time.RFC3339Nano)),
				zap.String("latency", strconv.FormatInt(int64(stop.Sub(start)), 10)),
				zap.String("latency_human", stop.Sub(start).String()),
				zap.String("id", id),
				zap.Int("status", res.Status),
				zap.String("method", req.Method),
				zap.String("uri", req.RequestURI),
				zap.String("host", req.Host),
				zap.String("path", p),
				zap.String("remote_ip", c.RealIP()),
				zap.String("referer", req.Referer()),
				zap.String("user_agent", req.UserAgent()),
				zap.String("bytes_in", cl),
				zap.String("bytes_out", strconv.FormatInt(res.Size, 10)),
			}

			n := res.Status
			switch {
			case n >= 500:
				log.Error("Server error", fields...)
			case n >= 400:
				log.Warn("Client error", fields...)
			case n >= 300:
				log.Info("Redirection", fields...)
			default:
				log.Info("Success", fields...)
			}

			return nil
		}
	}
}
