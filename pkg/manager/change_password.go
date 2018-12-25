package manager

import (
	"auth-one-api/pkg/database"
	"auth-one-api/pkg/models"
	"github.com/go-redis/redis"
	"github.com/labstack/gommon/random"
	"github.com/sirupsen/logrus"
	"gopkg.in/mgo.v2/bson"
)

type ChangePasswordManager Config

func (m *ChangePasswordManager) ChangePasswordStart(form *models.ChangePasswordStartForm) (ott *models.OneTimeToken, error *models.CommonError) {
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

	os := models.NewOneTimeTokenService(m.Redis)

	return &models.OneTimeToken{
		Token: os.Create(64, 60, random.Alphanumeric),
		Code:  os.Create(6, 60, random.Numeric),
	}, nil
}

func (m *ChangePasswordManager) ChangePasswordVerify(form *models.ChangePasswordVerifyForm) (token *models.AuthToken, error *models.CommonError) {
	if form.ClientId == `incorrect` {
		return nil, &models.CommonError{Code: `client_id`, Message: `Client ID is incorrect`}
	}
	if form.Connection == `incorrect` {
		return nil, &models.CommonError{Code: `connection`, Message: `Connection is incorrect`}
	}
	if form.Code == `incorrect` {
		return nil, &models.CommonError{Code: `verification_code`, Message: `Verification code is incorrect`}
	}
	if form.Token == `incorrect` {
		return nil, &models.CommonError{Code: `token`, Message: `Token is incorrect`}
	}
	if form.Password == `incorrect` {
		return nil, &models.CommonError{Code: `password`, Message: `Password is incorrect`}
	}

	return &models.AuthToken{
		RefreshToken: `refreshtoken`,
		AccessToken:  `accesstoken`,
		ExpiresIn:    1575983364,
	}, nil
}

func InitChangePasswordManager(logger *logrus.Entry, db *database.Handler, r *redis.Client) ChangePasswordManager {
	m := ChangePasswordManager{
		Database: db,
		Redis:    r,
		Logger:   logger,
	}

	return m
}
