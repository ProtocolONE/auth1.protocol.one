package manager

import (
	"auth-one-api/pkg/database"
	"auth-one-api/pkg/helper"
	"auth-one-api/pkg/models"
	"fmt"
	"github.com/labstack/echo"
	"github.com/sirupsen/logrus"
	"gopkg.in/mgo.v2/bson"
	"net/http"
	"time"
)

type SignUpManager Config

func (m *SignUpManager) SignUp(ctx echo.Context, form *models.SignUpForm) (token *models.AuthToken, error *models.CommonError) {
	as := models.NewApplicationService(m.Database)
	a, err := as.Get(bson.ObjectIdHex(form.ClientID))
	if err != nil {
		m.Logger.Warning(fmt.Sprintf("Unable to get application [%s] with error: %s", form.ClientID, err.Error()))
		return nil, &models.CommonError{Code: `client_id`, Message: models.ErrorClientIdIncorrect}
	}

	ps, err := as.LoadPasswordSettings()
	if err != nil {
		m.Logger.Warning(fmt.Sprintf("Unable to load password settings an application [%s] with error: %s", form.ClientID, err.Error()))
		return nil, &models.CommonError{Code: `common`, Message: models.ErrorUnableValidatePassword}
	}
	if false == ps.IsValid(form.Password) {
		return nil, &models.CommonError{Code: `password`, Message: models.ErrorPasswordIncorrect}
	}

	be := models.NewBcryptEncryptor(&models.CryptConfig{Cost: ps.BcryptCost})
	ep, err := be.Digest(form.Password)
	if err != nil {
		m.Logger.Warning(fmt.Sprintf("Unable to crypt password [%s] an application [%s] with error: %s", form.Password, form.ClientID, err.Error()))
		return nil, &models.CommonError{Code: `password`, Message: models.ErrorCryptPassword}
	}

	uis := models.NewUserIdentityService(m.Database)
	ui, err := uis.Get(a, models.UserIdentityProviderPassword, "", form.Email)
	if ui != nil || (err != nil && err.Error() != "not found") {
		if err != nil {
			m.Logger.Warning(fmt.Sprintf("Unable to get user with identity [%s] an application [%s] with error: %s", form.Email, form.ClientID, err.Error()))
		}
		return nil, &models.CommonError{Code: `email`, Message: models.ErrorLoginIncorrect}
	}

	us := models.NewUserService(m.Database)
	u := &models.User{
		ID:            bson.NewObjectId(),
		AppID:         a.ID,
		Email:         form.Email,
		EmailVerified: false,
		Blocked:       false,
		LastIp:        ctx.RealIP(),
		LastLogin:     time.Now(),
		LoginsCount:   1,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}
	if err := us.Create(u); err != nil {
		m.Logger.Warning(fmt.Sprintf("Unable to create user with identity [%s] an application [%s] with error: %s", form.Email, form.ClientID, err.Error()))
		return nil, &models.CommonError{Code: `common`, Message: models.ErrorCreateUser}
	}

	ui = &models.UserIdentity{
		ID:         bson.NewObjectId(),
		UserID:     u.ID,
		AppID:      a.ID,
		ExternalID: form.Email,
		Provider:   models.UserIdentityProviderPassword,
		Connection: "initial",
		Credential: ep,
		Email:      form.Email,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}
	if err := uis.Create(ui); err != nil {
		m.Logger.Warning(fmt.Sprintf("Unable to create user identity [%s] an application [%s] with error: %s", form.Email, form.ClientID, err.Error()))
		return nil, &models.CommonError{Code: `common`, Message: models.ErrorCreateUserIdentity}
	}

	t, err := helper.CreateAuthToken(ctx, as, u)
	if err != nil {
		m.Logger.Warning(fmt.Sprintf("Unable to create user [%s] auth token an application [%s] with error: %s", u.ID, a.ID, err.Error()))
		return nil, &models.CommonError{Code: `common`, Message: err.Error()}
	}

	als := models.NewAuthLogService(m.Database)
	if err := als.Add(ctx, u, t.RefreshToken); err != nil {
		return nil, &models.CommonError{Code: `common`, Message: models.ErrorAddAuthLog}
	}

	cs, err := as.LoadSessionSettings()
	if err != nil {
		m.Logger.Warning(fmt.Sprintf("Unable to add user [%s] auth log an application [%s] with error: %s", u.ID, a.ID, err.Error()))
		return nil, &models.CommonError{Code: `common`, Message: models.ErrorCreateCookie}
	}
	c, err := models.NewCookie(a, u).Crypt(cs)
	if err != nil {
		m.Logger.Warning(fmt.Sprintf("Unable to create user [%s] cookie an application [%s] with error: %s", u.ID, a.ID, err.Error()))
		return nil, &models.CommonError{Code: `common`, Message: models.ErrorCreateCookie}
	}
	http.SetCookie(ctx.Response(), c)

	return t, nil
}

func InitSignUpManager(logger *logrus.Entry, h *database.Handler) SignUpManager {
	m := SignUpManager{
		Logger:   logger,
		Database: h,
	}

	return m
}
