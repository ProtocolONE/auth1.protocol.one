package api

import (
	"fmt"
	"net/http"

	"github.com/ProtocolONE/auth1.protocol.one/pkg/api/apierror"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/database"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/helper"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/manager"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/models"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/service"
	"github.com/labstack/echo/v4"
)

func InitLogin(cfg *Server) error {
	// cfg.Echo.GET("/login/form", loginPage)

	// g := cfg.Echo.Group("/api/authorize", func(next echo.HandlerFunc) echo.HandlerFunc {
	// 	return func(c echo.Context) error {
	// 		db := c.Get("database").(database.MgoSession)
	// 		c.Set("login_manager", manager.NewLoginManager(db, cfg.Registry))

	// 		return next(c)
	// 	}
	// })

	// g.GET("/link", authorizeLink)
	// g.GET("/result", authorizeResult)
	// g.GET("", authorize)

	s := NewSocial(cfg.Registry)

	cfg.Echo.GET("/api/providers", s.List)
	cfg.Echo.GET("/api/providers/:name/profile", s.Profile)
	// redirect based apis
	cfg.Echo.GET("/api/providers/:name/forward", s.Forward, apierror.Redirect("/error"))
	cfg.Echo.GET("/api/providers/:name/callback", s.Callback, apierror.Redirect("/error"))

	return nil
}

type Social struct {
	registry service.InternalRegistry
}

func NewSocial(r service.InternalRegistry) *Social {
	return &Social{r}
}

type ProviderInfo struct {
	Name string `json:"name"`
	// Url  string `json:"url"`
}

func (s *Social) List(ctx echo.Context) error {
	var challenge = ctx.QueryParam("login_challenge")

	db := ctx.Get("database").(database.MgoSession)
	m := manager.NewLoginManager(db, s.registry)

	ips, err := m.Providers(challenge)
	if err != nil {
		return err
	}

	var res []ProviderInfo
	for i := range ips {
		res = append(res, ProviderInfo{
			Name: ips[i].Name,
			// Url:  "",
		})
	}

	return ctx.JSON(http.StatusOK, res)
}

func (s *Social) Forward(ctx echo.Context) error {
	var (
		name      = ctx.Param("name")
		challenge = ctx.QueryParam("login_challenge")
		domain    = fmt.Sprintf("%s://%s", ctx.Scheme(), ctx.Request().Host)
	)

	db := ctx.Get("database").(database.MgoSession)
	m := manager.NewLoginManager(db, s.registry)

	url, err := m.ForwardUrl(challenge, name, domain)
	if err != nil {
		return err
	}

	return ctx.Redirect(http.StatusPermanentRedirect, url)
}

func (s *Social) Callback(ctx echo.Context) error {
	var (
		name = ctx.Param("name")
		req  struct {
			Code  string `query:"code"`
			State string `query:"state"`
		}
		domain = fmt.Sprintf("%s://%s", ctx.Scheme(), ctx.Request().Host)
	)

	db := ctx.Get("database").(database.MgoSession)
	m := manager.NewLoginManager(db, s.registry)

	if err := ctx.Bind(&req); err != nil {
		return apierror.InvalidRequest(err)
	}

	url, err := m.Callback(name, req.Code, req.State, domain)
	if err != nil {
		return err
	}

	return ctx.Redirect(http.StatusTemporaryRedirect, url)
}

func (s *Social) Profile(ctx echo.Context) error {
	var token = ctx.QueryParam("token")

	db := ctx.Get("database").(database.MgoSession)
	m := manager.NewLoginManager(db, s.registry)

	profile, err := m.Profile(token)
	if err != nil {
		return err
	}

	profile.HideSensitive()

	return ctx.JSON(http.StatusOK, profile)

}

func authorize(ctx echo.Context) error {
	form := new(models.AuthorizeForm)
	m := ctx.Get("login_manager").(*manager.LoginManager)

	if err := ctx.Bind(form); err != nil {
		return apierror.InvalidRequest(err)
	}

	if err := ctx.Validate(form); err != nil {
		return apierror.InvalidParameters(err)
	}

	url, err := m.Authorize(ctx, form)
	if err != nil {
		return err
	}

	return ctx.Redirect(http.StatusMovedPermanently, url)
}

func authorizeResult(ctx echo.Context) error {
	form := new(models.AuthorizeResultForm)
	m := ctx.Get("login_manager").(*manager.LoginManager)

	if err := ctx.Bind(form); err != nil {
		return apierror.InvalidRequest(err)
		// e := &models.GeneralError{
		// 	Code:    BadRequiredCodeCommon,
		// 	Message: models.ErrorInvalidRequestParameters,
		// }
		// ctx.Error(err)
		// return ctx.Render(http.StatusOK, "social_auth_result.html", map[string]interface{}{
		// 	"Result":  &manager.SocialAccountError,
		// 	"Payload": map[string]interface{}{"code": e.Code, "message": e.Message},
		// })
	}

	if err := ctx.Validate(form); err != nil {
		return apierror.InvalidParameters(err)
		// e := &models.GeneralError{
		// 	Code:    fmt.Sprintf(BadRequiredCodeField, helper.GetSingleError(err).Field()),
		// 	Message: models.ErrorRequiredField,
		// }
		// ctx.Error(err)
		// return ctx.Render(http.StatusOK, "social_auth_result.html", map[string]interface{}{
		// 	"Result":  &manager.SocialAccountError,
		// 	"Payload": map[string]interface{}{"code": e.Code, "message": e.Message},
		// })
	}

	t, err := m.AuthorizeResult(ctx, form)
	if err != nil {
		return err
		// ctx.Error(err.Err)
		// return ctx.Render(http.StatusOK, "social_auth_result.html", map[string]interface{}{
		// 	"Result":  &manager.SocialAccountError,
		// 	"Payload": map[string]interface{}{"code": err.Code, "message": err.Message},
		// })
	}

	return ctx.Render(http.StatusOK, "social_auth_result.html", map[string]interface{}{
		"Result":  t.Result,
		"Payload": t.Payload,
	})
}

func authorizeLink(ctx echo.Context) error {
	form := new(models.AuthorizeLinkForm)
	m := ctx.Get("login_manager").(*manager.LoginManager)

	if err := ctx.Bind(form); err != nil {
		e := &models.GeneralError{
			Code:    BadRequiredCodeCommon,
			Message: models.ErrorInvalidRequestParameters,
		}
		ctx.Error(err)
		return helper.JsonError(ctx, e)
	}

	if err := ctx.Validate(form); err != nil {
		e := &models.GeneralError{
			Code:    fmt.Sprintf(BadRequiredCodeField, helper.GetSingleError(err).Field()),
			Message: models.ErrorRequiredField,
		}
		ctx.Error(err)
		return helper.JsonError(ctx, e)
	}

	url, err := m.AuthorizeLink(ctx, form)
	if err != nil {
		ctx.Error(err.Err)
		return helper.JsonError(ctx, err)
	}

	return ctx.JSON(http.StatusOK, map[string]string{"url": url})
}

// func loginPage(ctx echo.Context) (err error) {
// 	form := new(models.LoginPageForm)

// 	if err := ctx.Bind(form); err != nil {
// 		ctx.Error(err)
// 		return ctx.HTML(http.StatusBadRequest, models.ErrorInvalidRequestParameters)
// 	}

// 	url, err := createAuthUrl(ctx, form)
// 	if err != nil {
// 		ctx.Error(err)
// 		return ctx.HTML(http.StatusInternalServerError, "Unable to authorize, please come back later")
// 	}

// 	return ctx.Redirect(http.StatusMovedPermanently, url)
// }

// func createAuthUrl(ctx echo.Context, form *models.LoginPageForm) (string, error) {
// 	scopes := []string{"openid"}
// 	if form.Scopes != "" {
// 		scopes = strings.Split(form.Scopes, " ")
// 	}

// 	if form.RedirectUri == "" {
// 		form.RedirectUri = fmt.Sprintf("%s://%s/oauth2/callback", ctx.Scheme(), ctx.Request().Host)
// 	}

// 	settings := jwtverifier.Config{
// 		ClientID:     form.ClientID,
// 		ClientSecret: "",
// 		Scopes:       scopes,
// 		RedirectURL:  form.RedirectUri,
// 		Issuer:       fmt.Sprintf("%s://%s", ctx.Scheme(), ctx.Request().Host),
// 	}
// 	jwtv := jwtverifier.NewJwtVerifier(settings)

// 	return jwtv.CreateAuthUrl(form.State), nil
// }
