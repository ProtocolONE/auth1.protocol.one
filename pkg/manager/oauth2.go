package manager

import (
	"auth-one-api/pkg/database"
	"auth-one-api/pkg/models"
	"github.com/globalsign/mgo/bson"
	"github.com/go-redis/redis"
	"github.com/gorilla/sessions"
	"github.com/labstack/echo"
	"github.com/ory/hydra/sdk/go/hydra"
	"github.com/ory/hydra/sdk/go/hydra/swagger"
	"go.uber.org/zap"
)

type OauthManager struct {
	logger              *zap.Logger
	redis               *redis.Client
	hydra               *hydra.CodeGenSDK
	session             *sessions.Session
	appService          *models.ApplicationService
	userService         *models.UserService
	userIdentityService *models.UserIdentityService
	mfaService          *models.MfaService
	authLogService      *models.AuthLogService
}

func NewOauthManager(logger *zap.Logger, db *database.Handler, redis *redis.Client, h *hydra.CodeGenSDK, s *sessions.Session) *OauthManager {
	m := &OauthManager{
		logger:              logger,
		redis:               redis,
		hydra:               h,
		session:             s,
		appService:          models.NewApplicationService(db),
		userService:         models.NewUserService(db),
		userIdentityService: models.NewUserIdentityService(db),
		mfaService:          models.NewMfaService(db),
		authLogService:      models.NewAuthLogService(db),
	}

	return m
}

func (m *OauthManager) CreateCsrfSession(ctx echo.Context) (csrf string, err error) {
	c := models.GetRandString(64)
	m.session.Values["csrf"] = c
	if err := sessions.Save(ctx.Request(), ctx.Response()); err != nil {
		m.logger.Error("Error saving session", zap.Error(err))
		return "", err
	}

	return c, nil
}

func (m *OauthManager) CleanCsrfSession(ctx echo.Context) error {
	m.session.Values["csrf"] = ""
	if err := sessions.Save(ctx.Request(), ctx.Response()); err != nil {
		m.logger.Error("Error saving session", zap.Error(err))
		return err
	}

	return nil
}

func (m *OauthManager) Auth(ctx echo.Context, form *models.Oauth2LoginSubmitForm) (string, models.ErrorInterface) {
	csrf := m.session.Values["csrf"]
	if form.Csrf != "" && csrf != form.Csrf {
		m.logger.Error(
			"Unable to get application",
			zap.Object("LoginForm", form),
		)
		return "", &models.CommonError{Code: `csrf`, Message: models.ErrorCsrfSignature}
	}

	req, _, err := m.hydra.GetLoginRequest(form.Challenge)
	if err != nil {
		m.logger.Error(
			"Unable to get client from login request",
			zap.Object("Oauth2LoginSubmitForm", form),
			zap.Error(err),
		)
		return "", &models.CommonError{Code: `common`, Message: models.ErrorLoginChallenge}
	}

	app, err := m.appService.Get(bson.ObjectIdHex(req.Client.ClientId))
	if err != nil {
		m.logger.Error(
			"Unable to get application",
			zap.Object("Oauth2LoginSubmitForm", form),
			zap.Error(err),
		)
		return "", &models.CommonError{Code: `client_id`, Message: models.ErrorClientIdIncorrect}
	}

	userIdentity, err := m.userIdentityService.Get(app, models.UserIdentityProviderPassword, "", form.Email)
	if err != nil {
		m.logger.Warn(
			"Unable to get user identity",
			zap.Object("Oauth2LoginSubmitForm", form),
			zap.Object("Application", app),
			zap.Error(err),
		)
	}

	if userIdentity == nil || err != nil {
		return "", &models.CommonError{Code: `email`, Message: models.ErrorLoginIncorrect}
	}

	ps, err := m.appService.LoadPasswordSettings()
	if err != nil {
		m.logger.Error(
			"Unable to load password settings for application",
			zap.Object("Oauth2LoginSubmitForm", form),
			zap.Error(err),
		)
		return "", &models.CommonError{Code: `common`, Message: models.ErrorUnableValidatePassword}
	}

	be := models.NewBcryptEncryptor(&models.CryptConfig{Cost: ps.BcryptCost})
	err = be.Compare(userIdentity.Credential, form.Password)
	if err != nil {
		m.logger.Error(
			"Unable to crypt password for application",
			zap.String("Password", form.Password),
			zap.Object("Oauth2LoginSubmitForm", form),
			zap.Error(err),
		)
		return "", &models.CommonError{Code: `password`, Message: models.ErrorPasswordIncorrect}
	}

	// TODO: Add MFA cases

	_, _, err = m.hydra.AcceptLoginRequest(form.Challenge, swagger.AcceptLoginRequest{Subject: userIdentity.UserID.Hex()})
	if err != nil {
		m.logger.Error(
			"Unable to accept login challenge",
			zap.Object("Oauth2LoginSubmitForm", form),
			zap.Error(err),
		)
		return "", &models.CommonError{Code: `common`, Message: models.ErrorPasswordIncorrect}
	}

	// TODO: What scope should be requested to send a person to accept them?
	// TODO: For now, we automatically agree with those that the user came with.

	reqACR, _, err := m.hydra.AcceptConsentRequest(form.Challenge, swagger.AcceptConsentRequest{GrantScope: req.RequestedScope})
	if err != nil {
		return "", &models.CommonError{Code: `common`, Message: models.ErrorPasswordIncorrect}
	}

	return reqACR.RedirectTo, nil
}

func (m *OauthManager) Consent(ctx echo.Context, form *models.Oauth2ConsentForm) (scopes []string, err error) {
	scopes, err = m.GetScopes()

	return scopes, nil
}

func (m *OauthManager) ConsentSubmit(ctx echo.Context, form *models.Oauth2ConsentSubmitForm) (url string, err error) {
	_, err = m.GetScopes()
	if err != nil {
		return "", err
	}

	req, _, err := m.hydra.AcceptConsentRequest(form.Challenge, swagger.AcceptConsentRequest{GrantScope: form.Scope})
	if err != nil {
		return "", err
	}

	return req.RedirectTo, nil
}

func (m *OauthManager) Introspect(ctx echo.Context, form *models.Oauth2IntrospectForm) (*models.Oauth2TokenIntrospection, error) {
	app, err := m.appService.Get(bson.ObjectIdHex(form.ClientID))
	if err != nil {
		m.logger.Error(
			"Unable to get application",
			zap.Object("Oauth2IntrospectForm", form),
			zap.Error(err),
		)
		return nil, &models.CommonError{Code: `client_id`, Message: models.ErrorClientIdIncorrect}
	}

	if app.AuthSecret != form.Secret {
		m.logger.Error(
			"Invalid secret key",
			zap.Object("Oauth2IntrospectForm", form),
			zap.Error(err),
		)
		return nil, &models.CommonError{Code: `secret`, Message: models.ErrorUnknownError}
	}

	client, _, err := m.hydra.AdminApi.IntrospectOAuth2Token(form.Token, "")
	if err != nil {
		m.logger.Error(
			"Unable to introspect token",
			zap.Object("Oauth2IntrospectForm", form),
			zap.Error(err),
		)
		return nil, err
	}

	return &models.Oauth2TokenIntrospection{client}, nil
}

func (m *OauthManager) GetScopes() (scopes []string, err error) {
	scopes = []string{"openid", "offline"}
	/*if err := m.loadRemoteScopes(scopes); err != nil {
		return nil, err
	}*/

	return scopes, nil
}

func (m *OauthManager) loadRemoteScopes(scopes []string) error {
	scopes = append(scopes, []string{"test1", "test2"}...)
	return nil
}
