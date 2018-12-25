package manager

import (
	"auth-one-api/pkg/database"
	"auth-one-api/pkg/models"
	"github.com/dgrijalva/jwt-go"
	"github.com/labstack/echo"
	"github.com/sirupsen/logrus"
	"gopkg.in/mgo.v2/bson"
	"net/http"
	"time"
)

type LoginManager Config

func (m *LoginManager) Authorize(form *models.AuthorizeForm) (ott *models.OneTimeToken, error models.ErrorInterface) {
	if form.ClientId == `incorrect` {
		return nil, &models.CommonError{Message: `Connection is incorrect`}
	}
	if form.Connection == `incorrect` {
		return nil, &models.CommonError{Message: `Connection is incorrect`}
	}
	if form.RedirectUri == `incorrect` {
		return nil, &models.CommonError{Message: `Redirect URI is incorrect`}
	}

	return &models.OneTimeToken{
		Token: `onetimetoken`,
	}, nil
}

func (m *LoginManager) AuthorizeResult(form *models.AuthorizeResultForm) (error models.ErrorInterface) {
	if form.ClientId == `incorrect` {
		return &models.CommonError{Code: `connection`, Message: `Connection is incorrect`}
	}
	if form.Connection == `incorrect` {
		return &models.CommonError{Code: `connection`, Message: `Connection is incorrect`}
	}
	if form.OTT == `incorrect` {
		return &models.CommonError{Code: `auth_one_ott`, Message: `OTT is incorrect`}
	}

	return nil
}

func (m *LoginManager) Login(ctx echo.Context, form *models.LoginForm) (token *models.AuthToken, error models.ErrorInterface) {
	if form.Email == `captcha@required.com` {
		return nil, &models.CaptchaRequiredError{Message: `Captcha required`}
	}
	if form.Captcha == `incorrect` {
		return nil, &models.CommonError{Code: `captcha`, Message: `Captcha is incorrect`}
	}
	if form.Email == `mfa@required.com` {
		return nil, &models.MFARequiredError{Message: `MFA required`}
	}
	if form.Email == `temporary@locked.com` {
		return nil, &models.TemporaryLockedError{Message: `Temporary locked`}
	}
	if form.Connection == `incorrect` {
		return nil, &models.CommonError{Code: `connection`, Message: `Connection is incorrect`}
	}

	a, err := models.NewApplicationService(m.Database).Get(bson.ObjectIdHex(form.ClientId))
	if err != nil {
		return nil, &models.CommonError{Code: `client_id`, Message: `Client ID is incorrect`}
	}

	us := models.NewUserService(m.Database)
	u, err := us.GetUserByEmail(*a, form.Email)
	if u == nil || err != nil {
		return nil, &models.CommonError{Code: `email`, Message: `Login is incorrect`}
	}

	ps := &models.PasswordSettings{
		BcryptCost:     10,
		Min:            4,
		Max:            10,
		RequireNumber:  true,
		RequireSpecial: true,
		RequireUpper:   true,
	}
	js := &models.JwtSettings{
		Key:    []byte("k33)%(7cltD:q.N4AyuXfjAuK{zO,nzP"),
		Method: jwt.SigningMethodHS256,
		TTL:    3600,
	}
	rts := &models.RefreshTokenSettings{
		Length: 256,
		TTL:    3600,
	}
	cs := &models.CookieSettings{
		Name: "X-AUTH-ONE-TOKEN",
		TTL:  2592000,
	}

	be := models.NewBcryptEncryptor(&models.CryptConfig{Cost: ps.BcryptCost})
	err = be.Compare(u.Password, form.Password)
	if err != nil {
		return nil, &models.CommonError{Code: `password`, Message: `Password is incorrect`}
	}

	jts := models.NewJwtTokenService(js)
	at, err := jts.Create(u)

	rtsrv := models.NewRefreshTokenService(rts)
	rt := rtsrv.Create(ctx.Request().UserAgent(), ctx.Request().RemoteAddr)

	als := models.NewAuthLogService(m.Database)
	if err := als.Add(rt); err != nil {
		return nil, &models.CommonError{Code: `common`, Message: `Unable to add auth log`}
	}

	c, err := models.NewCookie(a, u).Crypt(cs)
	if err != nil {
		return nil, &models.CommonError{Code: `common`, Message: `Unable to create cookie`}
	}
	http.SetCookie(ctx.Response(), c)

	return &models.AuthToken{
		RefreshToken: rt.Value,
		AccessToken:  at,
		ExpiresIn:    time.Now().Unix() + int64(js.TTL),
	}, nil
}

func InitLoginManager(logger *logrus.Entry, h *database.Handler) LoginManager {
	m := LoginManager{
		Database: h,
		Logger:   logger,
	}

	return m
}
