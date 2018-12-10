package helper

import (
	"auth-one-api/pkg/api/models"
	"github.com/labstack/echo"
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
