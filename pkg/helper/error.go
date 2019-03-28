package helper

import (
	"github.com/ProtocolONE/auth1.protocol.one/pkg/models"
	"github.com/labstack/echo/v4"
	"gopkg.in/go-playground/validator.v9"
)

func GetSingleError(err error) validator.FieldError {
	validationErrors := err.(validator.ValidationErrors)
	return validationErrors[0]
}

func NewErrorResponse(ctx echo.Context, httpCode int, errCode string, errMessage string) error {
	return ctx.JSON(httpCode, CreateError(errCode, errMessage))
}

func CreateError(errCode string, errMessage string) *models.CommonError {
	return &models.CommonError{
		Code:    errCode,
		Message: errMessage,
	}
}
