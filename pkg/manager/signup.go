package manager

import (
	"auth-one-api/pkg/database"
	"auth-one-api/pkg/helper"
	"auth-one-api/pkg/models"
	"github.com/labstack/echo"
	"go.uber.org/zap"
	"gopkg.in/mgo.v2/bson"
	"net/http"
	"time"
)

type SignUpManager struct {
	logger              *zap.Logger
	appService          *models.ApplicationService
	userService         *models.UserService
	userIdentityService *models.UserIdentityService
	authLogService      *models.AuthLogService
}

func InitSignUpManager(logger *zap.Logger, h *database.Handler) *SignUpManager {
	m := &SignUpManager{
		logger:              logger,
		appService:          models.NewApplicationService(h),
		userService:         models.NewUserService(h),
		userIdentityService: models.NewUserIdentityService(h),
		authLogService:      models.NewAuthLogService(h),
	}

	return m
}

func (m *SignUpManager) SignUp(ctx echo.Context, form *models.SignUpForm) (token *models.AuthToken, error *models.CommonError) {
	app, err := m.appService.Get(bson.ObjectIdHex(form.ClientID))
	if err != nil {
		m.logger.Error(
			"Unable to get application",
			zap.Object("SignUpForm", form),
			zap.Error(err),
		)

		return nil, &models.CommonError{Code: `client_id`, Message: models.ErrorClientIdIncorrect}
	}

	ps, err := m.appService.LoadPasswordSettings()
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

	ui, err := m.userIdentityService.Get(app, models.UserIdentityProviderPassword, "", form.Email)
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
		ID:         bson.NewObjectId(),
		UserID:     user.ID,
		AppID:      app.ID,
		ExternalID: form.Email,
		Provider:   models.UserIdentityProviderPassword,
		Connection: "initial",
		Credential: ep,
		Email:      form.Email,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
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

	cs, err := m.appService.LoadSessionSettings()
	if err != nil {
		m.logger.Error(
			"Unable to add user auth log to application",
			zap.Object("User", user),
			zap.Object("Application", app),
			zap.Error(err),
		)

		return nil, &models.CommonError{Code: `common`, Message: models.ErrorCreateCookie}
	}
	c, err := models.NewCookie(app, user).Crypt(cs)
	if err != nil {
		m.logger.Error(
			"Unable to create user cookie for application",
			zap.Object("User", user),
			zap.Object("Application", app),
			zap.Error(err),
		)

		return nil, &models.CommonError{Code: `common`, Message: models.ErrorCreateCookie}
	}
	http.SetCookie(ctx.Response(), c)

	return t, nil
}
