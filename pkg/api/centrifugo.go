package api

import (
	"net/http"
	"time"

	"github.com/ProtocolONE/auth1.protocol.one/pkg/config"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/service"
	"github.com/centrifugal/gocent"
	"github.com/labstack/echo/v4"
)

func InitCentrifugo(cfg *Server) error {
	c := NewCentrifugo(cfg)

	cfg.Echo.POST("/centrifugo/auth", c.Authentication)
	cfg.Echo.POST("/centrifugo/refresh", c.Refresh)

	return nil
}

type Centrifugo struct {
	registry service.InternalRegistry
	config   *config.Centrifugo
	client   *gocent.Client
}

func NewCentrifugo(cfg *Server) *Centrifugo {
	return &Centrifugo{
		registry: cfg.Registry,
		config:   cfg.Centrifugo,
	}
}

func (c *Centrifugo) Authentication(ctx echo.Context) error {
	println(ctx.Request().Header.Get("Authorization"))
	challenge, err := ctx.Request().Cookie("login_challenge")
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, map[string]interface{}{
			"result": map[string]string{
				"error": err.Error(),
			},
		})
	}

	ctx.Logger().Debug("Centrifugo User authenticated with login_challenge = " + challenge.Value)

	return ctx.JSON(http.StatusOK, map[string]interface{}{
		"result": map[string]interface{}{
			"user":      challenge.Value,
			"expire_at": time.Now().Add(time.Second * time.Duration(c.config.SessionTTL)).Unix(),
		},
	})
}

func (c *Centrifugo) Refresh(ctx echo.Context) error {
	challenge, err := ctx.Request().Cookie("login_challenge")
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, map[string]interface{}{
			"result": map[string]string{
				"error": err.Error(),
			},
		})
	}

	c.registry.CentrifugoService().Expired(challenge.Value)
	return ctx.JSON(http.StatusOK, map[string]interface{}{
		"disconnect": map[string]interface{}{
			"code":      4404,
			"reconnect": false,
			"reason":    "expired",
		},
	})
}
