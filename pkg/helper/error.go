package helper

import (
	"bytes"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/models"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/go-playground/validator.v9"
	"io/ioutil"
	"net/http"
)

// GetSingleError returns the first error from the list of validation errors.
func GetSingleError(err error) validator.FieldError {
	validationErrors := err.(validator.ValidationErrors)
	return validationErrors[0]
}

// JsonError returns the JSON errors based on GeneralError model.
func JsonError(ctx echo.Context, err *models.GeneralError) error {
	if err.HttpCode == 0 {
		err.HttpCode = http.StatusBadRequest
	}
	if err.Message == "" {
		err.Message = models.ErrorUnknownError
	}
	if err.Code == "" {
		err.Code = "common"
	}
	return ctx.JSON(err.HttpCode, err)
}

// ErrorHandler generates an error message and saves it to the log
// The logger must be previously installed in the Echo context.
func ErrorHandler(err error, c echo.Context) {
	req := c.Request()
	res := c.Response()

	reqBody := []byte{}
	if req.Body != nil { // Read
		reqBody, _ = ioutil.ReadAll(req.Body)
	}
	c.Request().Body = ioutil.NopCloser(bytes.NewBuffer(reqBody))

	id := req.Header.Get(echo.HeaderXRequestID)
	if id == "" {
		id = res.Header().Get(echo.HeaderXRequestID)
	}

	fields := []zapcore.Field{
		zap.Error(err),
		zap.Any("request", reqBody),
	}
	zap.L().Error("Server error", fields...)

	return
}
