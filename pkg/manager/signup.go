package manager

import (
	"auth-one-api/pkg/database"
	"auth-one-api/pkg/helper"
	"auth-one-api/pkg/models"
	"github.com/globalsign/mgo/bson"
	"github.com/go-redis/redis"
	"github.com/labstack/echo"
	"go.uber.org/zap"
	"time"
)

type SignUpManager struct {
	logger                  *zap.Logger
	redis                   *redis.Client
	appService              *models.ApplicationService
	userService             *models.UserService
	userIdentityService     *models.UserIdentityService
	authLogService          *models.AuthLogService
	identityProviderService *models.AppIdentityProviderService
}

func InitSignUpManager(logger *zap.Logger, h *database.Handler, redis *redis.Client) *SignUpManager {
	m := &SignUpManager{
		logger:              logger,
		redis:               redis,
		appService:          models.NewApplicationService(h),
		userService:         models.NewUserService(h),
		userIdentityService: models.NewUserIdentityService(h),
		authLogService:      models.NewAuthLogService(h),
	}

	return m
}

func (m *SignUpManager) SignUp(ctx echo.Context, form *models.SignUpForm) (token interface{}, error *models.CommonError) {
	app, err := m.appService.Get(bson.ObjectIdHex(form.ClientID))
	if err != nil {
		m.logger.Error(
			"Unable to get application",
			zap.Object("SignUpForm", form),
			zap.Error(err),
		)

		return nil, &models.CommonError{Code: `client_id`, Message: models.ErrorClientIdIncorrect}
	}

	ps, err := m.appService.GetPasswordSettings(app)
	if err != nil {
		m.logger.Error(
			"Unable to load password settings for application",
			zap.Object("SignUpForm", form),
			zap.Error(err),
		)

		return nil, &models.CommonError{Code: `common`, Message: models.ErrorUnableValidatePassword}
	}
	if false == ps.IsValid(form.Password) {
		return nil, &models.CommonError{Code: `password`, Message: models.ErrorPasswordIncorrect}
	}

	be := models.NewBcryptEncryptor(&models.CryptConfig{Cost: ps.BcryptCost})

	ep, err := be.Digest(form.Password)
	if err != nil {
		m.logger.Error(
			"Unable to crypt password",
			zap.String("Password", form.Password),
			zap.Object("SignUpForm", form),
			zap.Error(err),
		)

		return nil, &models.CommonError{Code: `password`, Message: models.ErrorCryptPassword}
	}

	ipc, err := m.identityProviderService.FindByTypeAndName(app, models.AppIdentityProviderTypePassword, models.AppIdentityProviderNameDefault)
	if err != nil {
		m.logger.Warn(
			"Unable to get identity provider",
			zap.Object("SignUpForm", form),
			zap.Error(err),
		)
	}

	ui, err := m.userIdentityService.Get(app, ipc, form.Email)
	if err != nil {
		m.logger.Error(
			"Unable to get user with identity for application",
			zap.Object("SignUpForm", form),
			zap.Error(err),
		)
	}

	if ui != nil || (err != nil && err.Error() != "not found") {
		return nil, &models.CommonError{Code: `email`, Message: models.ErrorLoginIncorrect}
	}

	user := &models.User{
		ID:            bson.NewObjectId(),
		AppID:         app.ID,
		Email:         form.Email,
		EmailVerified: false,
		Blocked:       false,
		LastIp:        ctx.RealIP(),
		LastLogin:     time.Now(),
		LoginsCount:   1,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	if err := m.userService.Create(user); err != nil {
		m.logger.Error(
			"Unable to create user with identity for application",
			zap.Object("SignUpForm", form),
			zap.Error(err),
		)

		return nil, &models.CommonError{Code: `common`, Message: models.ErrorCreateUser}
	}

	ui = &models.UserIdentity{
		ID:                 bson.NewObjectId(),
		UserID:             user.ID,
		ApplicationID:      app.ID,
		ExternalID:         form.Email,
		IdentityProviderID: ipc.ID,
		Credential:         ep,
		Email:              form.Email,
		CreatedAt:          time.Now(),
		UpdatedAt:          time.Now(),
	}
	if err := m.userIdentityService.Create(ui); err != nil {
		m.logger.Error(
			"Unable to create user identity for application",
			zap.Object("SignUpForm", form),
			zap.Error(err),
		)

		return nil, &models.CommonError{Code: `common`, Message: models.ErrorCreateUserIdentity}
	}

	t, err := helper.CreateAuthToken(ctx, m.appService, user)
	if err != nil {
		m.logger.Error(
			"Unable to create user auth token for application [%s] with error: %s",
			zap.Object("User", user),
			zap.Object("Application", app),
			zap.Error(err),
		)

		return nil, &models.CommonError{Code: `common`, Message: err.Error()}
	}

	if err := m.authLogService.Add(ctx, user, t.RefreshToken); err != nil {
		m.logger.Error(
			"Unable to add auth log for user",
			zap.Object("User", user),
			zap.Error(err),
		)

		return nil, &models.CommonError{Code: `common`, Message: models.ErrorAddAuthLog}
	}

	if form.RedirectUri != "" {
		ottSettings := &models.OneTimeTokenSettings{
			Length: 64,
			TTL:    3600,
		}
		os := models.NewOneTimeTokenService(m.redis, ottSettings)
		ott, err := os.Create(&t)
		if err != nil {
			m.logger.Error(
				"Unable to create one-time token for application",
				zap.Object("LoginForm", form),
				zap.Object("User", user),
				zap.Object("Application", app),
				zap.Error(err),
			)

			return nil, &models.CommonError{Code: `common`, Message: models.ErrorCannotCreateToken}
		}

		url, err := helper.PrepareRedirectUrl(form.RedirectUri, ott)
		if err != nil {
			m.logger.Error(
				"Unable to create redirect url",
				zap.Object("LoginForm", form),
				zap.Object("OneTimeToken", ott),
				zap.Error(err),
			)
			return nil, &models.CommonError{Code: `common`, Message: models.ErrorCannotCreateToken}
		}
		return &models.AuthRedirectUrl{Url: url}, nil
	}

	return t, nil
}
