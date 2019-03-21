package manager

import (
	"auth-one-api/pkg/database"
	"auth-one-api/pkg/models"
	"github.com/globalsign/mgo/bson"
	"github.com/go-redis/redis"
	"go.uber.org/zap"
)

type ChangePasswordManager struct {
	redis                   *redis.Client
	logger                  *zap.Logger
	appService              *models.ApplicationService
	userIdentityService     *models.UserIdentityService
	identityProviderService *models.AppIdentityProviderService
}

func NewChangePasswordManager(logger *zap.Logger, db *database.Handler, r *redis.Client) *ChangePasswordManager {
	m := &ChangePasswordManager{
		redis:                   r,
		logger:                  logger,
		appService:              models.NewApplicationService(db),
		userIdentityService:     models.NewUserIdentityService(db),
		identityProviderService: models.NewAppIdentityProviderService(db),
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

	ipc, err := m.identityProviderService.FindByTypeAndName(a, models.AppIdentityProviderTypePassword, models.AppIdentityProviderNameDefault)
	if err != nil {
		m.logger.Warn(
			"Unable to get identity provider",
			zap.Object("ChangePasswordStartForm", form),
			zap.Error(err),
		)
	}

	ui, err := m.userIdentityService.Get(a, ipc, form.Email)
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

	ps, err := m.appService.GetPasswordSettings(a)
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
		Length: ps.TokenLength,
		TTL:    ps.TokenTTL,
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

	ps, err := m.appService.GetPasswordSettings(a)
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
		Length: ps.TokenLength,
		TTL:    ps.TokenTTL,
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

	ipc, err := m.identityProviderService.FindByTypeAndName(a, models.AppIdentityProviderTypePassword, models.AppIdentityProviderNameDefault)
	if err != nil {
		m.logger.Warn(
			"Unable to get identity provider",
			zap.Object("ChangePasswordVerifyForm", form),
			zap.Error(err),
		)
	}

	ui, err := m.userIdentityService.Get(a, ipc, ts.Email)
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
