package api

import (
	"net/http"
	"time"

	"github.com/ProtocolONE/auth1.protocol.one/pkg/api/apierror"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/config"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/models"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/service"
	"github.com/centrifugal/gocent"
	"github.com/dgrijalva/jwt-go"
	"github.com/labstack/echo/v4"
)

func InitCentrifugo(cfg *Server) error {
	c := NewCentrifugo(cfg)

	cfg.Echo.POST("/api/websockets/token", c.Token)
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
	}
}

func (c *Centrifugo) Token(ctx echo.Context) error {
	challenge := ctx.QueryParam("login_challenge")
	if challenge == "" {
		return ctx.JSON(http.StatusBadRequest, map[string]interface{}{
			"error": "login_challenge not defined",
		})
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":       challenge,
		"expire_at": time.Now().Add(time.Second * 15).Unix(),
	})
	tokenString, err := token.SignedString(c.config.HMACSecret)
	if err != nil {
		return err
	}

	return ctx.JSON(http.StatusOK, map[string]interface{}{
		"token": tokenString,
	})
}

func (c *Centrifugo) Authentication(ctx echo.Context) error {
	challenge, err := ctx.Request().Cookie("login_challenge")
	if err != nil {
		println("error: " + err.Error())
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
			"expire_at": time.Now().Add(time.Minute * 15).Unix(),
		},
	})
}

func (c *Centrifugo) Refresh(ctx echo.Context) error {
	challenge, err := ctx.Request().Cookie("login_challenge")
	if err != nil {
		println("error: " + err.Error())
		return ctx.JSON(http.StatusBadRequest, map[string]interface{}{
			"result": map[string]string{
				"error": err.Error(),
			},
		})
	}

	t := &models.LauncherToken{}
	err = c.registry.LauncherTokenService().Get(challenge.Value, t)
	if err != nil {
		if err == apierror.NotFound {
			return ctx.JSON(http.StatusBadRequest, map[string]interface{}{
				"result": map[string]string{
					"error": err.Error(),
				},
			})
		}
	}

	return ctx.JSON(http.StatusOK, map[string]interface{}{
		"result": map[string]interface{}{
			"expire_at": time.Now().Add(time.Minute * 6).Unix(),
		},
	})
}
