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
	app, err := m.appService.Get(bson.ObjectIdHex(form.ClientID))
	if err != nil {
		m.logger.Warn(
			"Unable to receive client id",
			zap.Object("ChangePasswordStartForm", form),
			zap.Error(err),
		)

		return &models.CommonError{Code: `client_id`, Message: models.ErrorClientIdIncorrect}
	}

	ipc, err := m.identityProviderService.FindByTypeAndName(app, models.AppIdentityProviderTypePassword, models.AppIdentityProviderNameDefault)
	if err != nil {
		m.logger.Warn(
			"Unable to get identity provider",
			zap.Object("ChangePasswordStartForm", form),
			zap.Error(err),
		)
		return &models.CommonError{Code: `common`, Message: models.ErrorUnknownError}
	}

	ui, err := m.userIdentityService.Get(app, ipc, form.Email)
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

	ps, err := m.appService.GetPasswordSettings(app)
	if err != nil {
		m.logger.Warn(
			"Unable to load password settings an application",
			zap.Object("ChangePasswordStartForm", form),
			zap.Error(err),
		)
		return &models.CommonError{Code: `common`, Message: models.ErrorUnableChangePassword}
	}

	ottSettings := &models.OneTimeTokenSettings{
		Length: ps.TokenLength,
		TTL:    ps.TokenTTL,
	}
	ott := models.NewOneTimeTokenService(m.redis, ottSettings)
	token, err := ott.Create(&models.ChangePasswordTokenSource{Email: form.Email})
	if err != nil {
		m.logger.Warn(
			"Unable to create one time token settings",
			zap.Object("ChangePasswordStartForm", form),
			zap.Error(err),
		)
		return &models.CommonError{Code: `common`, Message: models.ErrorUnableCreateOttSettings}
	}

	m.logger.Info(
		"Change password token",
		zap.String("Token", token.Token),
		zap.Error(err),
	)

	return nil
}

func (m *ChangePasswordManager) ChangePasswordVerify(form *models.ChangePasswordVerifyForm) *models.CommonError {
	if form.PasswordRepeat != form.Password {
		return &models.CommonError{Code: `password_repeat`, Message: models.ErrorPasswordRepeat}
	}

	app, err := m.appService.Get(bson.ObjectIdHex(form.ClientID))
	if err != nil {
		m.logger.Warn(
			"Unable to get application",
			zap.Object("ChangePasswordVerifyForm", form),
			zap.Error(err),
		)
		return &models.CommonError{Code: `client_id`, Message: models.ErrorClientIdIncorrect}
	}

	ps, err := m.appService.GetPasswordSettings(app)
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

	ipc, err := m.identityProviderService.FindByTypeAndName(app, models.AppIdentityProviderTypePassword, models.AppIdentityProviderNameDefault)
	if err != nil {
		m.logger.Warn(
			"Unable to get identity provider",
			zap.Object("ChangePasswordVerifyForm", form),
			zap.Error(err),
		)
		return &models.CommonError{Code: `common`, Message: models.ErrorUnknownError}
	}

	ui, err := m.userIdentityService.Get(app, ipc, ts.Email)
	if err != nil {
		m.logger.Warn(
			"Unable to get user identity for the application",
			zap.String("Email", ts.Email),
			zap.Object("ChangePasswordVerifyForm", form),
			zap.Error(err),
		)
		return &models.CommonError{Code: `common`, Message: models.ErrorUnknownError}
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
