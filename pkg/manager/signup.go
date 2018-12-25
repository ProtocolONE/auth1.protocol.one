package manager

import (
	"auth-one-api/pkg/database"
	"auth-one-api/pkg/models"
	"github.com/dgrijalva/jwt-go"
	"github.com/labstack/echo"
	"github.com/labstack/gommon/random"
	"github.com/sirupsen/logrus"
	"gopkg.in/mgo.v2/bson"
	"net/http"
	"time"
)

type SignUpManager Config

func (m *SignUpManager) SignUp(ctx echo.Context, form *models.SignUpForm) (token *models.AuthToken, error *models.CommonError) {
	if form.Connection == `incorrect` {
		return nil, &models.CommonError{Code: `connection`, Message: `Connection is incorrect`}
	}

	ps := &models.PasswordSettings{
		BcryptCost:     10,
		Min:            4,
		Max:            10,
		RequireNumber:  true,
		RequireSpecial: true,
		RequireUpper:   true,
	}
	if false == ps.IsValid(form.Password) {
		return nil, &models.CommonError{Code: `password`, Message: `Password is incorrect`}
	}

	be := models.NewBcryptEncryptor(&models.CryptConfig{Cost: ps.BcryptCost})
	ep, err := be.Digest(form.Password)
	if err != nil {
		return nil, &models.CommonError{Code: `password`, Message: `Unable to crypt password`}
	}

	a, err := models.NewApplicationService(m.Database).Get(bson.ObjectIdHex(form.ClientId))
	if err != nil {
		return nil, &models.CommonError{Code: `client_id`, Message: `Client ID is incorrect`}
	}

	us := models.NewUserService(m.Database)
	if u, _ := us.GetUserByEmail(*a, form.Email); u != nil {
		return nil, &models.CommonError{Code: `email`, Message: `Login is incorrect`}
	}

	u := &models.User{
		ID:        bson.NewObjectId(),
		Email:     form.Email,
		Password:  ep,
		AppID:     a.Id,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := us.CreateUser(u); err != nil {
		return nil, &models.CommonError{Code: `common`, Message: `Unable to create user`}
	}

	js := models.NewJwtTokenService(&models.JwtSettings{
		Key:    []byte("k33)%(7cltD:q.N4AyuXfjAuK{zO,nzP"),
		Method: jwt.SigningMethodHS256,
		TTL:    3600,
	})
	at, err := js.Create(u)

	l := 256
	rt := &models.RefreshToken{
		Value:     random.New().String(uint8(l)),
		TTL:       2592000,
		UserAgent: ctx.Request().UserAgent(),
		IP:        ctx.Request().RemoteAddr,
	}
	als := models.NewAuthLogService(m.Database)
	if err := als.Add(rt); err != nil {
		return nil, &models.CommonError{Code: `common`, Message: `Unable to add auth log`}
	}

	c, err := models.NewCookie(a, u).Crypt(&models.CookieSettings{
		Name: "X-AUTH-ONE-TOKEN",
		TTL:  3600,
	})
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

func InitSignUpManager(logger *logrus.Entry, h *database.Handler) SignUpManager {
	m := SignUpManager{
		Logger:   logger,
		Database: h,
	}

	return m
}
