package manager

import (
	"auth-one-api/pkg/database"
	"auth-one-api/pkg/models"
	"github.com/go-redis/redis"
	"go.uber.org/zap"
	"gopkg.in/mgo.v2/bson"
)

type ChangePasswordManager Config

func (m *ChangePasswordManager) ChangePasswordStart(form *models.ChangePasswordStartForm) *models.CommonError {
	as := models.NewApplicationService(m.Database)
	a, err := as.Get(bson.ObjectIdHex(form.ClientID))

	if err != nil {
		m.Logger.Warn(
			"Unable to receive client id",
			zap.String("clientId", form.ClientID),
			zap.Error(err),
		)

		return &models.CommonError{Code: `client_id`, Message: models.ErrorClientIdIncorrect}
	}

	uis := models.NewUserIdentityService(m.Database)
	ui, err := uis.Get(a, models.UserIdentityProviderPassword, form.Connection, form.Email)

	if err != nil {
		m.Logger.Warn(
			"Unable to get user identity by email",
			zap.String("email", form.Email),
			zap.Error(err),
		)
	}

	if ui == nil || err != nil {
		// INFO: Do not need to disclose the login
		return nil
	}

	ps, err := as.LoadPasswordSettings()
	if err != nil {
		m.Logger.Warn(
			"Unable to load password settings an application",
			zap.String("clientId", form.ClientID),
			zap.Error(err),
		)

		return &models.CommonError{Code: `common`, Message: models.ErrorUnableChangePassword}
	}

	err = m.createOneTimeTokenSettings(form.Email, ps)
	if err != nil {
		m.Logger.Warn(
			"Unable to create one time token settings",
			zap.String("clientId", form.ClientID),
			zap.Error(err),
		)

		return &models.CommonError{Code: `common`, Message: models.ErrorUnableCreateOttSettings}
	}

	return nil
}

func (m *ChangePasswordManager) createOneTimeTokenSettings(email string, ps *models.PasswordSettings) error {
	ottSettings := &models.OneTimeTokenSettings{
		Length: ps.ChangeTokenLength,
		TTL:    ps.ChangeTokenTTL,
	}
	os := models.NewOneTimeTokenService(m.Redis, ottSettings)

	_, err := os.Create(&models.ChangePasswordTokenSource{Email: email})

	return err
}

func (m *ChangePasswordManager) ChangePasswordVerify(form *models.ChangePasswordVerifyForm) *models.CommonError {
	if form.PasswordRepeat != form.Password {
		return &models.CommonError{Code: `password_repeat`, Message: models.ErrorPasswordRepeat}
	}

	as := models.NewApplicationService(m.Database)
	a, err := as.Get(bson.ObjectIdHex(form.ClientID))
	if err != nil {
		m.Logger.Warn(
			"Unable to get application",
			zap.String("clientId", form.ClientID),
			zap.Error(err),
		)

		return &models.CommonError{Code: `client_id`, Message: models.ErrorClientIdIncorrect}
	}

	ps, err := as.LoadPasswordSettings()
	if err != nil {
		m.Logger.Warn(
			"Unable to get app password settings",
			zap.String("clientId", form.ClientID),
			zap.Error(err),
		)

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
		m.Logger.Warn(
			"Unable to use token of application",
			zap.String("clientId", form.ClientID),
			zap.Error(err),
		)

		return &models.CommonError{Code: `common`, Message: models.ErrorCannotUseToken}
	}

	uis := models.NewUserIdentityService(m.Database)
	ui, err := uis.Get(a, models.UserIdentityProviderPassword, form.Connection, ts.Email)

	if err != nil {
		m.Logger.Warn(
			"Unable to get user identity for the application",
			zap.String("email", ts.Email),
			zap.String("clientId", form.ClientID),
			zap.Error(err),
		)
	}

	if ui == nil || err != nil {
		return &models.CommonError{Code: `common`, Message: models.ErrorCannotUseToken}
	}

	be := models.NewBcryptEncryptor(&models.CryptConfig{Cost: ps.BcryptCost})
	ui.Credential, err = be.Digest(form.Password)

	if err != nil {
		m.Logger.Warn(
			"Unable to crypt password in application",
			zap.String("password", form.Password),
			zap.String("clientId", form.ClientID),
			zap.Error(err),
		)

		return &models.CommonError{Code: `password`, Message: models.ErrorCryptPassword}
	}

	if err = uis.Update(ui); err != nil {
		m.Logger.Warn(
			"Unable to update user identity password",
			zap.String("id", ui.ID.String()),
			zap.Error(err),
		)

		return &models.CommonError{Code: `password`, Message: models.ErrorUnableChangePassword}
	}

	return nil
}

func InitChangePasswordManager(logger *zap.Logger, db *database.Handler, r *redis.Client) ChangePasswordManager {
	m := ChangePasswordManager{
		Database: db,
		Redis:    r,
		Logger:   logger,
	}

	return m
}
