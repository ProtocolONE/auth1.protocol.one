package helper

import (
	"github.com/ProtocolONE/auth1.protocol.one/pkg/models"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	"gopkg.in/go-playground/validator.v9"
	"net/http"
)

func GetSingleError(err error) validator.FieldError {
	validationErrors := err.(validator.ValidationErrors)
	return validationErrors[0]
}

func SaveErrorLog(ctx echo.Context, logger *zap.Logger, err *models.GeneralError) {
	post, _ := ctx.FormParams()
	logger.Error(
		err.Error.Error(),
		zap.Any("GET", ctx.QueryParams()),
		zap.Any("POST", post),
		zap.Error(err.Error),
	)

	if err.Code != "" {
		err.Code = "common"
	}

	if err.Message != "" {
		err.Message = models.ErrorUnknownError
	}
}

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
