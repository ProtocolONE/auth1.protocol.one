package apierror

import (
	"fmt"
	"net/http"

	"github.com/labstack/echo/v4"
)

type Error struct {
	Code    int
	Message string
	Status  uint16
}

func (e Error) Error() string {
	return e.Message
}

const ErrorPrefix = "errors.one.protocol.auth1."

var (
	unknown           = Error{1000, "unknown", http.StatusInternalServerError}
	invalidRequest    = Error{1001, "invalid_request", http.StatusBadRequest}
	invalidParameters = Error{1002, "invalid_parameters", http.StatusBadRequest}
)

func Unknown(err error) error {
	return invalidRequest
}

func InvalidRequest(err error) error {
	return invalidRequest
}

func InvalidParameters(err error) error {
	return invalidParameters
}

type Params *interface{}

type Response struct {
	Error     string `json:"error"`
	Code      string `json:"code"`
	RequestID string `json:"request_id"`
	Params
}

func Handler(err error, ctx echo.Context) {
	rid := ctx.Response().Header().Get(echo.HeaderXRequestID)

	var code = http.StatusInternalServerError
	var resp Response

	switch e := err.(type) {
	case Error:
		resp.Error = ErrorPrefix + e.Message
		resp.Code = fmt.Sprintf("AU-%d", e.Code)
		resp.RequestID = rid
		code = int(e.Status)
	}

	var m interface{} = map[string]interface{}{"param": "some"}
	resp.Params = &m

	// Send response
	if !ctx.Response().Committed {
		if ctx.Request().Method == http.MethodHead { // Issue #608
			err = ctx.NoContent(code)
		} else {
			err = ctx.JSON(code, resp)
		}
		if err != nil {
			ctx.Logger().Error(err)
		}
	}
}
