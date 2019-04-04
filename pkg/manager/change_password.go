package manager

import (
	"github.com/ProtocolONE/auth1.protocol.one/pkg/models"
	"github.com/globalsign/mgo"
	"github.com/globalsign/mgo/bson"
	"github.com/go-redis/redis"
	"go.uber.org/zap"
)

type ChangePasswordManager struct {
	redis               *redis.Client
	logger              *zap.Logger
	appService          *models.ApplicationService
	userIdentityService *models.UserIdentityService
}

func NewChangePasswordManager(db *mgo.Session, l *zap.Logger, r *redis.Client) *ChangePasswordManager {
	m := &ChangePasswordManager{
		redis:               r,
		logger:              l,
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
			zap.Object("ChangePasswordStartForm", form),
			zap.Error(err),
		)

		return &models.CommonError{Code: `client_id`, Message: models.ErrorClientIdIncorrect}
	}

	ui, err := m.userIdentityService.Get(a, models.UserIdentityProviderPassword, form.Connection, form.Email)

	if err != nil {
		m.logger.Warn(
			"Unable to get user identity by email",
			zap.Object("ChangePasswordStartForm", form),
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
			zap.Object("ChangePasswordStartForm", form),
			zap.Error(err),
		)

		return &models.CommonError{Code: `common`, Message: models.ErrorUnableChangePassword}
	}

	err = m.createOneTimeTokenSettings(form.Email, ps)
	if err != nil {
		m.logger.Warn(
			"Unable to create one time token settings",
			zap.Object("ChangePasswordStartForm", form),
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
			zap.Object("ChangePasswordVerifyForm", form),
			zap.Error(err),
		)

		return &models.CommonError{Code: `client_id`, Message: models.ErrorClientIdIncorrect}
	}

	ps, err := m.appService.LoadPasswordSettings()
	if err != nil {
		m.logger.Warn(
			"Unable to get app password settings",
			zap.Object("ChangePasswordVerifyForm", form),
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
			zap.Object("ChangePasswordVerifyForm", form),
			zap.Error(err),
		)

		return &models.CommonError{Code: `common`, Message: models.ErrorCannotUseToken}
	}

	ui, err := m.userIdentityService.Get(a, models.UserIdentityProviderPassword, form.Connection, ts.Email)

	if err != nil {
		m.logger.Warn(
			"Unable to get user identity for the application",
			zap.String("Email", ts.Email),
			zap.Object("ChangePasswordVerifyForm", form),
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
			zap.String("Password", form.Password),
			zap.Object("ChangePasswordVerifyForm", form),
			zap.Error(err),
		)

		return &models.CommonError{Code: `password`, Message: models.ErrorCryptPassword}
	}

	if err = m.userIdentityService.Update(ui); err != nil {
		m.logger.Warn(
			"Unable to update user identity password",
			zap.Object("UserIdentity", ui),
			zap.Error(err),
		)

		return &models.CommonError{Code: `password`, Message: models.ErrorUnableChangePassword}
	}

	return nil
}
