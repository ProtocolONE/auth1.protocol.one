package api

import (
	"net/http"
	"time"

	"github.com/ProtocolONE/auth1.protocol.one/pkg/api/apierror"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/config"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/models"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/service"
	"github.com/centrifugal/gocent"
	"github.com/labstack/echo/v4"
)

func InitCentrifugo(cfg *Server) error {
	c := NewCentrifugo(cfg)

	cfg.Echo.GET("/api/ws", c.Html)
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

func (c *Centrifugo) Html(ctx echo.Context) error {
	ch := ctx.QueryParam("ch")
	return ctx.HTML(http.StatusOK, `<html>
<head>

</head>
<body onload="onLoad()">
<script src="https://cdn.rawgit.com/centrifugal/centrifuge-js/2.4.0/dist/centrifuge.min.js"></script>
<script type="application/javascript">
    function onLoad() {
        document.cookie = "login_challenge=`+ch+`; path=/";
        var centrifuge = new Centrifuge('ws://localhost:7001/centrifugo/websocket',{
            debug: true
        });
        centrifuge.subscribe("launcher#`+ch+`", function(message) {
            console.log(message);
        });

        centrifuge.connect();
    }
</script>
</body>
</html>
`)
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
			"expire_at": time.Now().Add(time.Second * time.Duration(c.config.SessionTTL)).Unix(),
		},
	})
}
