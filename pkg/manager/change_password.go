package manager

import (
	"auth-one-api/pkg/database"
	"auth-one-api/pkg/models"
	"github.com/go-redis/redis"
	"go.uber.org/zap"
	"gopkg.in/mgo.v2/bson"
)

type ChangePasswordManager struct {
	redis               *redis.Client
	logger              *zap.Logger
	appService          *models.ApplicationService
	userIdentityService *models.UserIdentityService
}

func NewChangePasswordManager(logger *zap.Logger, db *database.Handler, r *redis.Client) *ChangePasswordManager {
	m := &ChangePasswordManager{
		redis:               r,
		logger:              logger,
		appService:          models.NewApplicationService(db),
		userIdentityService: models.NewUserIdentityService(db),
	}

	return m
}

func (m *ChangePasswordManager) ChangePasswordStart(form *models.ChangePasswordStartForm) *models.CommonError {
	a, err := m.appService.Get(bson.ObjectIdHex(form.ClientID))

	if err != nil {
		m.logger.Warn(
			"Unable to receive client id",
			zap.Object("form", form),
			zap.Error(err),
		)

		return &models.CommonError{Code: `client_id`, Message: models.ErrorClientIdIncorrect}
	}

	ui, err := m.userIdentityService.Get(a, models.UserIdentityProviderPassword, form.Connection, form.Email)

	if err != nil {
		m.logger.Warn(
			"Unable to get user identity by email",
			zap.Object("form", form),
			zap.Error(err),
		)
	}

	if ui == nil || err != nil {
		// INFO: Do not need to disclose the login
		return nil
	}

	ps, err := m.appService.LoadPasswordSettings()
	if err != nil {
		m.logger.Warn(
			"Unable to load password settings an application",
			zap.Object("clientId", form),
			zap.Error(err),
		)

		return &models.CommonError{Code: `common`, Message: models.ErrorUnableChangePassword}
	}

	err = m.createOneTimeTokenSettings(form.Email, ps)
	if err != nil {
		m.logger.Warn(
			"Unable to create one time token settings",
			zap.Object("form", form),
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
	os := models.NewOneTimeTokenService(m.redis, ottSettings)

	_, err := os.Create(&models.ChangePasswordTokenSource{Email: email})

	return err
}

func (m *ChangePasswordManager) ChangePasswordVerify(form *models.ChangePasswordVerifyForm) *models.CommonError {
	if form.PasswordRepeat != form.Password {
		return &models.CommonError{Code: `password_repeat`, Message: models.ErrorPasswordRepeat}
	}

	a, err := m.appService.Get(bson.ObjectIdHex(form.ClientID))
	if err != nil {
		m.logger.Warn(
			"Unable to get application",
			zap.Object("form", form),
			zap.Error(err),
		)

		return &models.CommonError{Code: `client_id`, Message: models.ErrorClientIdIncorrect}
	}

	ps, err := m.appService.LoadPasswordSettings()
	if err != nil {
		m.logger.Warn(
			"Unable to get app password settings",
			zap.Object("form", form),
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

	os := models.NewOneTimeTokenService(m.redis, ottSettings)
	ts := &models.ChangePasswordTokenSource{}

	if err := os.Use(form.Token, ts); err != nil {
		m.logger.Warn(
			"Unable to use token of application",
			zap.Object("form", form),
			zap.Error(err),
		)

		return &models.CommonError{Code: `common`, Message: models.ErrorCannotUseToken}
	}

	ui, err := m.userIdentityService.Get(a, models.UserIdentityProviderPassword, form.Connection, ts.Email)

	if err != nil {
		m.logger.Warn(
			"Unable to get user identity for the application",
			zap.String("email", ts.Email),
			zap.Object("form", form),
			zap.Error(err),
		)
	}

	if ui == nil || err != nil {
		return &models.CommonError{Code: `common`, Message: models.ErrorCannotUseToken}
	}

	be := models.NewBcryptEncryptor(&models.CryptConfig{Cost: ps.BcryptCost})
	ui.Credential, err = be.Digest(form.Password)

	if err != nil {
		m.logger.Warn(
			"Unable to crypt password in application",
			zap.String("password", form.Password),
			zap.Object("form", form),
			zap.Error(err),
		)

		return &models.CommonError{Code: `password`, Message: models.ErrorCryptPassword}
	}

	if err = m.userIdentityService.Update(ui); err != nil {
		m.logger.Warn(
			"Unable to update user identity password",
			zap.Object("userIdentity", ui),
			zap.Error(err),
		)

		return &models.CommonError{Code: `password`, Message: models.ErrorUnableChangePassword}
	}

	return nil
}
