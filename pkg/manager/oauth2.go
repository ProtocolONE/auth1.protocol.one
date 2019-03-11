package manager

import (
	"auth-one-api/pkg/database"
	"auth-one-api/pkg/models"
	"fmt"
	"github.com/ProtocolONE/authone-jwt-verifier-golang"
	"github.com/globalsign/mgo/bson"
	"github.com/go-redis/redis"
	"github.com/gorilla/sessions"
	"github.com/labstack/echo"
	"github.com/ory/hydra/sdk/go/hydra"
	"github.com/ory/hydra/sdk/go/hydra/swagger"
	"go.uber.org/zap"
	"net/http"
	"time"
)

var (
	loginRememberKey   = "login_remember"
	clientIdSessionKey = "oauth_client_id"
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

func (m *OauthManager) CheckAuth(ctx echo.Context, form *models.Oauth2LoginForm) (string, models.ErrorInterface) {
	req, _, err := m.hydra.GetLoginRequest(form.Challenge)
	if err != nil {
		m.logger.Error(
			"Unable to get client from login request",
			zap.Object("Oauth2LoginForm", form),
			zap.Error(err),
		)
		return "", &models.CommonError{Code: `common`, Message: models.ErrorLoginChallenge}
	}

	if req.Skip == false {
		return "", nil
	}

	reqACL, _, err := m.hydra.AcceptLoginRequest(form.Challenge, swagger.AcceptLoginRequest{Subject: req.Subject})
	if err != nil {
		m.logger.Error(
			"Unable to accept login challenge",
			zap.Object("Oauth2LoginSubmitForm", form),
			zap.Error(err),
		)
		return "", &models.CommonError{Code: `common`, Message: models.ErrorPasswordIncorrect}
	}

	return reqACL.RedirectTo, nil
}

func (m *OauthManager) Auth(ctx echo.Context, form *models.Oauth2LoginSubmitForm) (string, models.ErrorInterface) {
	csrf := m.session.Values["csrf"]
	if form.Csrf != "" && csrf != form.Csrf {
		m.logger.Error(
			"Unable to get application",
			zap.Object("Oauth2LoginSubmitForm", form),
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

	passwordSettings, err := m.appService.LoadPasswordSettings()
	if err != nil {
		m.logger.Error(
			"Unable to load password settings for application",
			zap.Object("Oauth2LoginSubmitForm", form),
			zap.Error(err),
		)
		return "", &models.CommonError{Code: `common`, Message: models.ErrorUnableValidatePassword}
	}

	encryptor := models.NewBcryptEncryptor(&models.CryptConfig{Cost: passwordSettings.BcryptCost})
	err = encryptor.Compare(userIdentity.Credential, form.Password)
	if err != nil {
		m.logger.Error(
			"Unable to crypt password for application",
			zap.String("Password", form.Password),
			zap.Object("Oauth2LoginSubmitForm", form),
			zap.Error(err),
		)
		return "", &models.CommonError{Code: `password`, Message: models.ErrorPasswordIncorrect}
	}

	user, err := m.userService.Get(userIdentity.UserID)
	if err != nil {
		m.logger.Error(
			"Unable to get user",
			zap.Object("UserIdentity", userIdentity),
			zap.Error(err),
		)

		return "", &models.CommonError{Code: `email`, Message: models.ErrorLoginIncorrect}
	}

	if err := m.authLogService.Add(ctx, user, ""); err != nil {
		m.logger.Error(
			"Unable to add auth log for user",
			zap.Object("User", user),
			zap.Error(err),
		)

		return "", &models.CommonError{Code: `common`, Message: models.ErrorAddAuthLog}
	}

	cookieSettings, err := m.appService.LoadSessionSettings()
	if err != nil {
		m.logger.Error(
			"Unable to add user auth log to application",
			zap.Object("User", user),
			zap.Object("Application", app),
			zap.Error(err),
		)

		return "", &models.CommonError{Code: `common`, Message: models.ErrorCreateCookie}
	}
	cookie, err := models.NewCookie(app, user).Crypt(cookieSettings)
	if err != nil {
		m.logger.Error(
			"Unable to create user cookie for application",
			zap.Object("User", user),
			zap.Object("Application", app),
			zap.Error(err),
		)

		return "", &models.CommonError{Code: `common`, Message: models.ErrorCreateCookie}
	}
	http.SetCookie(ctx.Response(), cookie)

	m.session.Values[loginRememberKey] = form.Remember
	if err := sessions.Save(ctx.Request(), ctx.Response()); err != nil {
		m.logger.Error("Error saving session", zap.Error(err))
	}

	// TODO: Add MFA cases

	reqACL, _, err := m.hydra.AcceptLoginRequest(form.Challenge, swagger.AcceptLoginRequest{Subject: userIdentity.UserID.Hex(), Remember: form.Remember, RememberFor: 0})
	if err != nil {
		m.logger.Error(
			"Unable to accept login challenge",
			zap.Object("Oauth2LoginSubmitForm", form),
			zap.Error(err),
		)
		return "", &models.CommonError{Code: `common`, Message: models.ErrorPasswordIncorrect}
	}

	return reqACL.RedirectTo, nil
}

func (m *OauthManager) Consent(ctx echo.Context, form *models.Oauth2ConsentForm) (string, error) {
	scopes, err := m.GetScopes()
	// TODO: What scope should be requested to send a person to accept them?
	// TODO: For now, we automatically agree with those that the user came with.

	reqGCR, _, err := m.hydra.GetConsentRequest(form.Challenge)
	if err != nil {
		m.logger.Error(
			"Unable to get consent challenge",
			zap.Object("Oauth2ConsentForm", form),
			zap.Error(err),
		)
		return "", &models.CommonError{Code: `common`, Message: models.ErrorPasswordIncorrect}
	}

	req := swagger.AcceptConsentRequest{}
	if reqGCR.Skip == true {
		req = swagger.AcceptConsentRequest{
			GrantScope: scopes,
			Session: swagger.ConsentRequestSession{
				AccessToken: map[string]interface{}{"remember": true},
			},
		}
	} else {
		req = swagger.AcceptConsentRequest{
			GrantScope: scopes,
			Remember:   m.session.Values[loginRememberKey].(bool),
			Session: swagger.ConsentRequestSession{
				AccessToken: map[string]interface{}{"remember": m.session.Values[loginRememberKey].(bool)},
			},
		}
	}

	reqACR, _, err := m.hydra.AcceptConsentRequest(form.Challenge, req)
	if err != nil {
		m.logger.Error(
			"Unable to accept consent challenge",
			zap.Object("Oauth2ConsentForm", form),
			zap.Error(err),
		)
		return "", &models.CommonError{Code: `common`, Message: models.ErrorPasswordIncorrect}
	}

	return reqACR.RedirectTo, nil
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

func (m *OauthManager) SignUp(ctx echo.Context, form *models.Oauth2SignUpForm) (string, models.ErrorInterface) {
	csrf := m.session.Values["csrf"]
	if form.Csrf != "" && csrf != form.Csrf {
		m.logger.Error(
			"Unable to get application",
			zap.Object("Oauth2SignUpForm", form),
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

	passwordSettings, err := m.appService.LoadPasswordSettings()
	if err != nil {
		m.logger.Error(
			"Unable to load password settings for application",
			zap.Object("SignUpForm", form),
			zap.Error(err),
		)

		return "", &models.CommonError{Code: `common`, Message: models.ErrorUnableValidatePassword}
	}
	if false == passwordSettings.IsValid(form.Password) {
		return "", &models.CommonError{Code: `password`, Message: models.ErrorPasswordIncorrect}
	}

	encryptor := models.NewBcryptEncryptor(&models.CryptConfig{Cost: passwordSettings.BcryptCost})

	ep, err := encryptor.Digest(form.Password)
	if err != nil {
		m.logger.Error(
			"Unable to crypt password",
			zap.String("Password", form.Password),
			zap.Object("SignUpForm", form),
			zap.Error(err),
		)

		return "", &models.CommonError{Code: `password`, Message: models.ErrorCryptPassword}
	}

	userIdentity, err := m.userIdentityService.Get(app, models.UserIdentityProviderPassword, "", form.Email)
	if err != nil {
		m.logger.Error(
			"Unable to get user with identity for application",
			zap.Object("SignUpForm", form),
			zap.Error(err),
		)
	}

	if userIdentity != nil || (err != nil && err.Error() != "not found") {
		return "", &models.CommonError{Code: `email`, Message: models.ErrorLoginIncorrect}
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

		return "", &models.CommonError{Code: `common`, Message: models.ErrorCreateUser}
	}

	userIdentity = &models.UserIdentity{
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
	if err := m.userIdentityService.Create(userIdentity); err != nil {
		m.logger.Error(
			"Unable to create user identity for application",
			zap.Object("SignUpForm", form),
			zap.Error(err),
		)

		return "", &models.CommonError{Code: `common`, Message: models.ErrorCreateUserIdentity}
	}

	if err := m.authLogService.Add(ctx, user, ""); err != nil {
		m.logger.Error(
			"Unable to add auth log for user",
			zap.Object("User", user),
			zap.Error(err),
		)

		return "", &models.CommonError{Code: `common`, Message: models.ErrorAddAuthLog}
	}

	cookieSettings, err := m.appService.LoadSessionSettings()
	if err != nil {
		m.logger.Error(
			"Unable to add user auth log to application",
			zap.Object("User", user),
			zap.Object("Application", app),
			zap.Error(err),
		)

		return "", &models.CommonError{Code: `common`, Message: models.ErrorCreateCookie}
	}
	cookie, err := models.NewCookie(app, user).Crypt(cookieSettings)
	if err != nil {
		m.logger.Error(
			"Unable to create user cookie for application",
			zap.Object("User", user),
			zap.Object("Application", app),
			zap.Error(err),
		)

		return "", &models.CommonError{Code: `common`, Message: models.ErrorCreateCookie}
	}
	http.SetCookie(ctx.Response(), cookie)

	reqACL, _, err := m.hydra.AcceptLoginRequest(form.Challenge, swagger.AcceptLoginRequest{Subject: userIdentity.ID.Hex()})
	if err != nil {
		m.logger.Error(
			"Unable to accept login challenge",
			zap.Object("Oauth2LoginSubmitForm", form),
			zap.Error(err),
		)
		return "", &models.CommonError{Code: `common`, Message: models.ErrorPasswordIncorrect}
	}

	return reqACL.RedirectTo, nil
}

func (m *OauthManager) CallBack(ctx echo.Context, form *models.Oauth2CallBackForm) *models.Oauth2CallBackResponse {
	clientId := m.session.Values[clientIdSessionKey].(string)
	if clientId == "" {
		m.logger.Error(
			"Unable to get client id from session",
			zap.Object("Oauth2CallBackForm", form),
		)
		return &models.Oauth2CallBackResponse{
			Success:      false,
			ErrorMessage: `unknown_client_id`,
		}
	}

	app, err := m.appService.Get(bson.ObjectIdHex(clientId))
	if err != nil {
		m.logger.Error(
			"Unable to get application",
			zap.Object("Oauth2CallBackForm", form),
			zap.Error(err),
		)
		return &models.Oauth2CallBackResponse{
			Success:      false,
			ErrorMessage: `invalid_client_id`,
		}
	}

	settings := jwtverifier.Config{
		ClientID:     clientId,
		ClientSecret: app.AuthSecret,
		RedirectURL:  fmt.Sprintf("%s://%s/oauth2/callback", ctx.Scheme(), ctx.Request().Host),
		Issuer:       fmt.Sprintf("%s://%s", ctx.Scheme(), ctx.Request().Host),
	}
	jwtv := jwtverifier.NewJwtVerifier(settings)
	tokens, err := jwtv.Exchange(ctx.Request().Context(), form.Code)
	if err != nil {
		return &models.Oauth2CallBackResponse{
			Success:      false,
			ErrorMessage: `unable_exchange_code`,
		}
	}

	expIn := 0
	if tokens.AccessToken != "" {
		expIn = int(tokens.Expiry.Sub(time.Now()).Seconds())
	}

	return &models.Oauth2CallBackResponse{
		Success:     true,
		AccessToken: tokens.AccessToken,
		IdToken:     tokens.Extra("id_token").(string),
		ExpiresIn:   expIn,
	}
}

func (m *OauthManager) loadRemoteScopes(scopes []string) error {
	scopes = append(scopes, []string{"test1", "test2"}...)
	return nil
}
