package apierror

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/pkg/errors"

	"github.com/ProtocolONE/auth1.protocol.one/pkg/appcore/log"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
)

// Response represents json response for api errors
type Response struct {
	*APIError
	RequestID string `json:"request_id,omitempty"`
}

func Middleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			defer func() {
				if r := recover(); r != nil {
					err, ok := r.(error)
					if !ok {
						err = fmt.Errorf("%v", r)
					}
					Handler(errors.WithStack(err), c)
				}
			}()
			err := next(c)
			if err != nil {
				Handler(err, c)
			}
			return nil
		}
	}
}

// Handler represents echo error handler for api
func Handler(err error, ctx echo.Context) {
	if ctx.Response().Committed {
		log.Error(ctx.Request().Context(), "Response already commited", zap.Error(err))
		return
	}

	var e *APIError
	if !errors.As(err, &e) {
		switch err {
		case echo.ErrMethodNotAllowed:
			e = MethodNotAllowed
		case echo.ErrNotFound:
			e = NotFound
		case echo.ErrUnauthorized:
			e = Unauthorized
		default:
			log.Error(ctx.Request().Context(), "Unknown api error", zap.Error(err))
			e = unknown
		}
	}

	if err := resp(ctx, e); err != nil {
		log.Error(ctx.Request().Context(), "API response failure", zap.Error(err))
	}
}

// resp generates server response for error
func resp(ctx echo.Context, e *APIError) error {
	var code = e.Status
	if ctx.Request().Method == http.MethodHead {
		return ctx.NoContent(code)
	}

	rid := ctx.Response().Header().Get(echo.HeaderXRequestID)
	var resp = Response{
		RequestID: rid,
		APIError:  e,
	}
	return ctx.JSON(code, resp)
}

func Redirect(path string) echo.MiddlewareFunc {
	_, err := url.Parse(path)
	if err != nil {
		panic(err)
	}
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(ctx echo.Context) error {
			err := next(ctx)
			if err == nil {
				return nil
			}

			var e *APIError
			if !errors.As(err, &e) {
				log.Error(ctx.Request().Context(), "Unknown api error", zap.Error(err))
				e = unknown
			}

			u, err := url.Parse(path)
			if err != nil {
				panic(err)
			}
			v := u.Query()
			v.Add("error", e.Message)
			v.Add("code", e.Code)
			u.RawQuery = v.Encode()
			return ctx.Redirect(http.StatusTemporaryRedirect, u.String())
		}
	}
}
