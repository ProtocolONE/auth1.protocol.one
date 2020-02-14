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

	InvalidChallenge = Error{1003, "invalid_challenge", http.StatusBadRequest}
	InvalidToken     = Error{1004, "invalid_token", http.StatusBadRequest}
	InvalidClient    = Error{1005, "invalid_client", http.StatusBadRequest}
	InvalidEmail     = Error{1006, "invalid_email", http.StatusBadRequest}
	InvalidPassword  = Error{1007, "invalid_password", http.StatusBadRequest}
	UsernameTaken    = Error{1008, "username_already_exists", http.StatusBadRequest}
	WeakPassword     = Error{1009, "password_does_not_meet_policy", http.StatusBadRequest}
	EmailRegistered  = Error{1010, "email_already_registered", http.StatusBadRequest}
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

type Response struct {
	Error     string `json:"error"`
	Code      string `json:"code"`
	RequestID string `json:"request_id"`
}

func Handler(err error, ctx echo.Context) {
	rid := ctx.Response().Header().Get(echo.HeaderXRequestID)

	var e Error
	if x, ok := err.(Error); ok {
		e = x
	} else {
		ctx.Logger().Error(err)
		e = unknown
	}

	var resp = Response{
		Error:     ErrorPrefix + e.Message,
		Code:      fmt.Sprintf("AU-%d", e.Code),
		RequestID: rid,
	}
	var code = int(e.Status)

	// Send response
	if !ctx.Response().Committed {
		if ctx.Request().Method == http.MethodHead {
			err = ctx.NoContent(code)
		} else {
			err = ctx.JSON(code, resp)
		}
		if err != nil {
			ctx.Logger().Error(err)
		}
	}
}
