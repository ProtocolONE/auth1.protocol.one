package manager

import (
	"fmt"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/config"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/models"
	"github.com/ProtocolONE/authone-jwt-verifier-golang"
	"github.com/globalsign/mgo"
	"github.com/globalsign/mgo/bson"
	"github.com/go-redis/redis"
	"github.com/gorilla/sessions"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
	"github.com/ory/hydra/sdk/go/hydra"
	"github.com/ory/hydra/sdk/go/hydra/swagger"
	"go.uber.org/zap"
	"net/http"
	"time"
)

var (
	loginRememberKey   = "login_remember"
	clientIdSessionKey = "oauth_client_id"
	logoutSessionKey   = "oauth_logout_redirect_uri"
	logoutHydraUrl     = "/oauth2/auth/sessions/login/revoke"
)

type OauthManager struct {
	redis               *redis.Client
	hydra               *hydra.CodeGenSDK
	sessionConfig       *config.SessionConfig
	appService          *models.ApplicationService
	userService         *models.UserService
	userIdentityService *models.UserIdentityService
	mfaService          *models.MfaService
	authLogService      *models.AuthLogService
}

func NewOauthManager(db *mgo.Session, redis *redis.Client, h *hydra.CodeGenSDK, s *config.SessionConfig) *OauthManager {
	m := &OauthManager{
		redis:               redis,
		hydra:               h,
		sessionConfig:       s,
		appService:          models.NewApplicationService(db),
		userService:         models.NewUserService(db),
		userIdentityService: models.NewUserIdentityService(db),
		mfaService:          models.NewMfaService(db),
		authLogService:      models.NewAuthLogService(db),
	}

	return m
}

func (m *OauthManager) CheckAuth(ctx echo.Context, form *models.Oauth2LoginForm) (*models.User, string, models.ErrorInterface) {
	req, _, err := m.hydra.GetLoginRequest(form.Challenge)
	if err != nil {
		zap.L().Error(
			"Unable to get client from login request",
			zap.Object("Oauth2LoginForm", form),
			zap.Error(err),
		)
		return nil, "", &models.CommonError{Code: `common`, Message: models.ErrorLoginChallenge}
	}

	if req.Subject == "" {
		return nil, "", nil
	}

	sess, err := session.Get(m.sessionConfig.Name, ctx)
	if err != nil {
		zap.L().Error("Unable to get session", zap.Error(err))
		return nil, "", &models.CommonError{Code: `common`, Message: models.ErrorUnknownError}
	}
	sess.Values[loginRememberKey] = req.Skip == true
	if err := sessions.Save(ctx.Request(), ctx.Response()); err != nil {
		zap.L().Error("Error saving session", zap.Error(err))
		return nil, "", &models.CommonError{Code: `common`, Message: models.ErrorUnknownError}
	}

	if req.Skip == true {
		reqACL, _, err := m.hydra.AcceptLoginRequest(form.Challenge, swagger.AcceptLoginRequest{Subject: req.Subject})
		if err != nil {
			zap.L().Error(
				"Unable to accept login challenge",
				zap.Object("Oauth2LoginForm", form),
				zap.Error(err),
			)
			return nil, "", &models.CommonError{Code: `common`, Message: models.ErrorPasswordIncorrect}
		}

		return nil, reqACL.RedirectTo, nil
	}

	app, err := m.appService.Get(bson.ObjectIdHex(req.Client.ClientId))
	if err != nil {
		zap.L().Error(
			"Unable to get application",
			zap.Object("Oauth2LoginForm", form),
			zap.Error(err),
		)
		return nil, "", &models.CommonError{Code: `client_id`, Message: models.ErrorClientIdIncorrect}
	}

	user, err := m.userService.Get(bson.ObjectIdHex(req.Subject))
	if err != nil {
		zap.L().Warn(
			"Unable to get user identity",
			zap.Object("Oauth2LoginSubmitForm", form),
			zap.Object("Application", app),
			zap.Error(err),
		)
	}

	return user, "", nil
}

func (m *OauthManager) Auth(ctx echo.Context, form *models.Oauth2LoginSubmitForm) (string, models.ErrorInterface) {
	sess, err := session.Get(m.sessionConfig.Name, ctx)
	if err != nil {
		zap.L().Error("Unable to get session", zap.Error(err))
		return "", &models.CommonError{Code: `common`, Message: models.ErrorUnknownError}
	}

	req, _, err := m.hydra.GetLoginRequest(form.Challenge)
	if err != nil {
		zap.L().Error(
			"Unable to get client from login request",
			zap.Object("Oauth2LoginSubmitForm", form),
			zap.Error(err),
		)
		return "", &models.CommonError{Code: `common`, Message: models.ErrorLoginChallenge}
	}

	userId := req.Subject
	if req.Subject == "" || req.Subject != form.PreviousLogin {
		app, err := m.appService.Get(bson.ObjectIdHex(req.Client.ClientId))
		if err != nil {
			zap.L().Error(
				"Unable to get application",
				zap.Object("Oauth2LoginSubmitForm", form),
				zap.Error(err),
			)
			return "", &models.CommonError{Code: `client_id`, Message: models.ErrorClientIdIncorrect}
		}

		userIdentity, err := m.userIdentityService.Get(app, models.UserIdentityProviderPassword, "", form.Email)
		if err != nil {
			zap.L().Warn(
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
			zap.L().Error(
				"Unable to load password settings for application",
				zap.Object("Oauth2LoginSubmitForm", form),
				zap.Error(err),
			)
			return "", &models.CommonError{Code: `common`, Message: models.ErrorUnableValidatePassword}
		}

		encryptor := models.NewBcryptEncryptor(&models.CryptConfig{Cost: passwordSettings.BcryptCost})
		err = encryptor.Compare(userIdentity.Credential, form.Password)
		if err != nil {
			zap.L().Error(
				"Unable to crypt password for application",
				zap.String("Password", form.Password),
				zap.Object("Oauth2LoginSubmitForm", form),
				zap.Error(err),
			)
			return "", &models.CommonError{Code: `password`, Message: models.ErrorPasswordIncorrect}
		}

		user, err := m.userService.Get(userIdentity.UserID)
		if err != nil {
			zap.L().Error(
				"Unable to get user",
				zap.Object("UserIdentity", userIdentity),
				zap.Error(err),
			)

			return "", &models.CommonError{Code: `email`, Message: models.ErrorLoginIncorrect}
		}

		if err := m.authLogService.Add(ctx, user, ""); err != nil {
			zap.L().Error(
				"Unable to add auth log for user",
				zap.Object("User", user),
				zap.Error(err),
			)

			return "", &models.CommonError{Code: `common`, Message: models.ErrorAddAuthLog}
		}
		userId = userIdentity.UserID.Hex()
	} else {
		form.Remember = true
	}

	sess.Values[loginRememberKey] = form.Remember
	if err := sessions.Save(ctx.Request(), ctx.Response()); err != nil {
		zap.L().Error("Error saving session", zap.Error(err))
		return "", &models.CommonError{Code: `common`, Message: models.ErrorUnknownError}
	}

	// TODO: Add MFA cases

	reqACL, _, err := m.hydra.AcceptLoginRequest(
		form.Challenge,
		swagger.AcceptLoginRequest{
			Subject:     userId,
			Remember:    form.Remember,
			RememberFor: 0,
		},
	)
	if err != nil {
		zap.L().Error(
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
		zap.L().Error(
			"Unable to get consent challenge",
			zap.Object("Oauth2ConsentForm", form),
			zap.Error(err),
		)
		return "", &models.CommonError{Code: `common`, Message: models.ErrorPasswordIncorrect}
	}

	user, err := m.userService.Get(bson.ObjectIdHex(reqGCR.Subject))
	if err != nil {
		zap.L().Error(
			"Unable to get user",
			zap.String("Subject", reqGCR.Subject),
			zap.Error(err),
		)

		return "", &models.CommonError{Code: `email`, Message: models.ErrorLoginIncorrect}
	}

	sess, err := session.Get(m.sessionConfig.Name, ctx)
	if err != nil {
		zap.L().Error("Unable to get session", zap.Error(err))
		return "", &models.CommonError{Code: `common`, Message: models.ErrorUnknownError}
	}

	req := swagger.AcceptConsentRequest{GrantScope: scopes}
	userInfo := map[string]interface{}{
		"email":                 user.Email,
		"email_verified":        user.EmailVerified,
		"phone_number":          user.PhoneNumber,
		"phone_number_verified": user.PhoneVerified,
		"name":                  user.Name,
		"picture":               user.Picture,
	}
	if reqGCR.Skip == true {
		req.Session = swagger.ConsentRequestSession{
			AccessToken: map[string]interface{}{"remember": true},
			IdToken:     userInfo,
		}
	} else {
		req.Session = swagger.ConsentRequestSession{
			AccessToken: map[string]interface{}{"remember": sess.Values[loginRememberKey].(bool)},
			IdToken:     userInfo,
		}
	}

	reqACR, _, err := m.hydra.AcceptConsentRequest(form.Challenge, req)
	if err != nil {
		zap.L().Error(
			"Unable to accept consent challenge",
			zap.Object("Oauth2ConsentForm", form),
			zap.Error(err),
		)
		return "", &models.CommonError{Code: `common`, Message: models.ErrorPasswordIncorrect}
	}

	sess.Values[clientIdSessionKey] = reqGCR.Client.ClientId
	if err := sess.Save(ctx.Request(), ctx.Response()); err != nil {
		zap.L().Error("Error saving session", zap.Error(err))
		return "", err
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
		zap.L().Error(
			"Unable to get application",
			zap.Object("Oauth2IntrospectForm", form),
			zap.Error(err),
		)
		return nil, &models.CommonError{Code: `client_id`, Message: models.ErrorClientIdIncorrect}
	}

	if app.AuthSecret != form.Secret {
		zap.L().Error(
			"Invalid secret key",
			zap.Object("Oauth2IntrospectForm", form),
			zap.Error(err),
		)
		return nil, &models.CommonError{Code: `secret`, Message: models.ErrorUnknownError}
	}

	client, _, err := m.hydra.AdminApi.IntrospectOAuth2Token(form.Token, "")
	if err != nil {
		zap.L().Error(
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
	sess, err := session.Get(m.sessionConfig.Name, ctx)
	if err != nil {
		zap.L().Error("Unable to get session", zap.Error(err))
		return "", &models.CommonError{Code: `common`, Message: models.ErrorUnknownError}
	}

	sess.Values[loginRememberKey] = form.Remember
	if err := sess.Save(ctx.Request(), ctx.Response()); err != nil {
		zap.L().Error("Error saving session", zap.Error(err))
	}

	req, _, err := m.hydra.GetLoginRequest(form.Challenge)
	if err != nil {
		zap.L().Error(
			"Unable to get client from login request",
			zap.Object("Oauth2LoginSubmitForm", form),
			zap.Error(err),
		)
		return "", &models.CommonError{Code: `common`, Message: models.ErrorLoginChallenge}
	}

	app, err := m.appService.Get(bson.ObjectIdHex(req.Client.ClientId))
	if err != nil {
		zap.L().Error(
			"Unable to get application",
			zap.Object("Oauth2LoginSubmitForm", form),
			zap.Error(err),
		)
		return "", &models.CommonError{Code: `client_id`, Message: models.ErrorClientIdIncorrect}
	}

	passwordSettings, err := m.appService.LoadPasswordSettings()
	if err != nil {
		zap.L().Error(
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
		zap.L().Error(
			"Unable to crypt password",
			zap.String("Password", form.Password),
			zap.Object("SignUpForm", form),
			zap.Error(err),
		)

		return "", &models.CommonError{Code: `password`, Message: models.ErrorCryptPassword}
	}

	userIdentity, err := m.userIdentityService.Get(app, models.UserIdentityProviderPassword, "", form.Email)
	if err != nil && err != mgo.ErrNotFound {
		zap.L().Error(
			"Unable to get user with identity for application",
			zap.Object("SignUpForm", form),
			zap.Error(err),
		)
	}

	if userIdentity != nil && userIdentity.ID.Hex() != "" {
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
		zap.L().Error(
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
		zap.L().Error(
			"Unable to create user identity for application",
			zap.Object("SignUpForm", form),
			zap.Error(err),
		)

		return "", &models.CommonError{Code: `common`, Message: models.ErrorCreateUserIdentity}
	}

	if err := m.authLogService.Add(ctx, user, ""); err != nil {
		zap.L().Error(
			"Unable to add auth log for user",
			zap.Object("User", user),
			zap.Error(err),
		)

		return "", &models.CommonError{Code: `common`, Message: models.ErrorAddAuthLog}
	}

	cookieSettings, err := m.appService.LoadSessionSettings()
	if err != nil {
		zap.L().Error(
			"Unable to add user auth log to application",
			zap.Object("User", user),
			zap.Object("Application", app),
			zap.Error(err),
		)

		return "", &models.CommonError{Code: `common`, Message: models.ErrorCreateCookie}
	}
	cookie, err := models.NewCookie(app, user).Crypt(cookieSettings)
	if err != nil {
		zap.L().Error(
			"Unable to create user cookie for application",
			zap.Object("User", user),
			zap.Object("Application", app),
			zap.Error(err),
		)

		return "", &models.CommonError{Code: `common`, Message: models.ErrorCreateCookie}
	}
	http.SetCookie(ctx.Response(), cookie)

	reqACL, _, err := m.hydra.AcceptLoginRequest(form.Challenge, swagger.AcceptLoginRequest{Subject: user.ID.Hex()})
	if err != nil {
		zap.L().Error(
			"Unable to accept login challenge",
			zap.Object("Oauth2LoginSubmitForm", form),
			zap.Error(err),
		)
		return "", &models.CommonError{Code: `common`, Message: models.ErrorPasswordIncorrect}
	}

	return reqACL.RedirectTo, nil
}

func (m *OauthManager) CallBack(ctx echo.Context, form *models.Oauth2CallBackForm) *models.Oauth2CallBackResponse {
	sess, err := session.Get(m.sessionConfig.Name, ctx)
	if err != nil {
		zap.L().Error("Unable to get session", zap.Error(err))
		return &models.Oauth2CallBackResponse{
			Success:      false,
			ErrorMessage: `unknown_client_id`,
		}
	}
	clientId := sess.Values[clientIdSessionKey].(string)
	if clientId == "" {
		zap.L().Error(
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
		zap.L().Error(
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

func (m *OauthManager) Logout(ctx echo.Context, form *models.Oauth2LogoutForm) (string, error) {
	sess, err := session.Get(m.sessionConfig.Name, ctx)
	if err != nil {
		zap.L().Error("Unable to get session", zap.Error(err))
		return "", &models.CommonError{Code: `common`, Message: models.ErrorUnknownError}
	}

	logoutRedirectUri := sess.Values[logoutSessionKey]
	if form.RedirectUri == "" {
		form.RedirectUri = "auth1"
	}
	if logoutRedirectUri == "" || logoutRedirectUri == nil {
		sess.Values[logoutSessionKey] = form.RedirectUri
		if err := sess.Save(ctx.Request(), ctx.Response()); err != nil {
			zap.L().Error("Error saving session", zap.Error(err))
			return "", err
		}
		return logoutHydraUrl, nil
	}

	sess.Values[logoutSessionKey] = ""
	if err := sess.Save(ctx.Request(), ctx.Response()); err != nil {
		zap.L().Error("Error saving sessionConfig", zap.Error(err))
		return "", err
	}

	if logoutRedirectUri != "auth1" {
		return logoutRedirectUri.(string), nil
	}

	return "", nil
}

func (m *OauthManager) loadRemoteScopes(scopes []string) error {
	scopes = append(scopes, []string{"test1", "test2"}...)
	return nil
}
