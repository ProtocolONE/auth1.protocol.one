package api

import (
	"net/http"

	"github.com/ProtocolONE/auth1.protocol.one/pkg/database"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/models"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/service"
	"github.com/labstack/echo/v4"
)

func InitSignup(cfg *Server) error {
	cfg.Echo.POST("/signup/checkUsername", checkUsername)

	return nil
}

func checkUsername(ctx echo.Context) error {
	var r struct {
		Username string `json:"username"`
	}

	if err := ctx.Bind(&r); err != nil {
		ctx.Error(err)
		return ctx.HTML(http.StatusBadRequest, models.ErrorInvalidRequestParameters)
	}

	db := ctx.Get("database").(database.MgoSession)
	users := service.NewUserService(db)
	ok, err := users.IsUsernameFree(r.Username)
	if err != nil {
		ctx.Error(err)
		return ctx.JSON(http.StatusInternalServerError, map[string]interface{}{})
	}

	if ok {
		return ctx.JSON(http.StatusOK, map[string]interface{}{})
	}

	return ctx.JSON(http.StatusForbidden, map[string]interface{}{})
}
