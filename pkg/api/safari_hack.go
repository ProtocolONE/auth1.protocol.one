package api

import (
	"github.com/labstack/echo/v4"
	"net/http"
)

func InitSafariHack(cfg *Server) error {
	cfg.Echo.GET("/safari_hack", SafariHack)

	return nil
}

func SafariHack(ctx echo.Context) error {
	return ctx.HTML(http.StatusOK, `
		<script>
			document.cookie = 'safari_cookie_fix=fixed; path=/';
			if (window.location.href.indexOf('verbose') > -1) {
				setTimeout(window.location.replace(document.referrer), 2000);
			} else {
				window.location.replace(document.referrer) //>>>>>>> leave this line ONLY <<<<<<<<
			}
		</script>
	`)
}
