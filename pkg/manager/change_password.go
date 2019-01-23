package manager

import (
	"auth-one-api/pkg/database"
	"auth-one-api/pkg/models"
	"fmt"
	"github.com/go-redis/redis"
	"github.com/sirupsen/logrus"
	"gopkg.in/mgo.v2/bson"
)

type ChangePasswordManager Config

func (m *ChangePasswordManager) ChangePasswordStart(form *models.ChangePasswordStartForm) *models.CommonError {
	as := models.NewApplicationService(m.Database)
	a, err := as.Get(bson.ObjectIdHex(form.ClientID))
	if err != nil {
		m.Logger.Warning(fmt.Sprintf("Unable to receive client id [%s] with error: %s", form.ClientID, err.Error()))
		return &models.CommonError{Code: `client_id`, Message: models.ErrorClientIdIncorrect}
	}

	uis := models.NewUserIdentityService(m.Database)
	ui, err := uis.Get(a, models.UserIdentityProviderPassword, form.Connection, form.Email)
	if ui == nil || err != nil {
		if err != nil {
			m.Logger.Warning(fmt.Sprintf("Unable to get user identity by email [%s] with error: %s", form.Email, err.Error()))
		}
		// INFO: Do not need to disclose the login
		return nil
	}

	ps, err := as.LoadPasswordSettings()
	if err != nil {
		m.Logger.Warning(fmt.Sprintf("Unable to load password settings an application [%s] with error: %s", form.ClientID, err.Error()))
		return &models.CommonError{Code: `common`, Message: models.ErrorUnableChangePassword}
	}
	ottSettings := &models.OneTimeTokenSettings{
		Length: ps.ChangeTokenLength,
		TTL:    ps.ChangeTokenTTL,
	}
	os := models.NewOneTimeTokenService(m.Redis, ottSettings)
	os.Create(&models.ChangePasswordTokenSource{
		Email: form.Email,
	})

	return nil
}

func (m *ChangePasswordManager) ChangePasswordVerify(form *models.ChangePasswordVerifyForm) *models.CommonError {
	if form.PasswordRepeat != form.Password {
		return &models.CommonError{Code: `password_repeat`, Message: models.ErrorPasswordRepeat}
	}

	as := models.NewApplicationService(m.Database)
	a, err := as.Get(bson.ObjectIdHex(form.ClientID))
	if err != nil {
		m.Logger.Warning(fmt.Sprintf("Unable to get application [%s] with error: %s", form.ClientID, err.Error()))
		return &models.CommonError{Code: `client_id`, Message: models.ErrorClientIdIncorrect}
	}

	ps, err := as.LoadPasswordSettings()
	if err != nil {
		m.Logger.Warning(fmt.Sprintf("Unable to get app password settings [%s] with error: %s", form.ClientID, err.Error()))
		return &models.CommonError{Code: `common`, Message: models.ErrorUnableValidatePassword}
	}

	if false == ps.IsValid(form.Password) {
		return &models.CommonError{Code: `password`, Message: models.ErrorPasswordIncorrect}
	}

	ottSettings := &models.OneTimeTokenSettings{
		Length: ps.ChangeTokenLength,
		TTL:    ps.ChangeTokenTTL,
	}
	os := models.NewOneTimeTokenService(m.Redis, ottSettings)
	ts := &models.ChangePasswordTokenSource{}
	if err := os.Use(form.Token, ts); err != nil {
		m.Logger.Warning(fmt.Sprintf("Unable to use token an application [%s] with error: %s", form.ClientID, err.Error()))
		return &models.CommonError{Code: `common`, Message: models.ErrorCannotUseToken}
	}

	uis := models.NewUserIdentityService(m.Database)
	ui, err := uis.Get(a, models.UserIdentityProviderPassword, form.Connection, ts.Email)
	if ui == nil || err != nil {
		if err != nil {
			m.Logger.Warning(fmt.Sprintf("Unable to get user identity [%s] an application [%s] with error: %s", ts.Email, form.ClientID, err.Error()))
		}
		return &models.CommonError{Code: `common`, Message: models.ErrorCannotUseToken}
	}

	be := models.NewBcryptEncryptor(&models.CryptConfig{Cost: ps.BcryptCost})
	ui.Credential, err = be.Digest(form.Password)
	if err != nil {
		m.Logger.Warning(fmt.Sprintf("Unable to crypt password [%s] an application [%s] with error: %s", form.Password, form.ClientID, err.Error()))
		return &models.CommonError{Code: `password`, Message: models.ErrorCryptPassword}
	}

	if err = uis.Update(ui); err != nil {
		m.Logger.Warning(fmt.Sprintf("Unable to update user identity [%s] password with error: %s", ui.ID, err.Error()))
		return &models.CommonError{Code: `password`, Message: models.ErrorUnableChangePassword}
	}

	return nil
}

func InitChangePasswordManager(logger *logrus.Entry, db *database.Handler, r *redis.Client) ChangePasswordManager {
	m := ChangePasswordManager{
		Database: db,
		Redis:    r,
		Logger:   logger,
	}

	return m
}
