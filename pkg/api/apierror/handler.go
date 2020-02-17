package apierror

import (
	"net/http"

	"errors"

	"github.com/labstack/echo/v4"
)

// Response represents json response for api errors
type Response struct {
	*APIError
	RequestID string `json:"request_id,omitempty"`
}

// Handler represents echo error handler for api
func Handler(err error, ctx echo.Context) {
	if ctx.Response().Committed {
		ctx.Logger().Error("response already commited", err)
		return
	}

	var e *APIError
	if !errors.As(err, &e) {
		ctx.Logger().Error(err)
		e = unknown
	}

	if err := resp(ctx, e); err != nil {
		ctx.Logger().Error(err)
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
