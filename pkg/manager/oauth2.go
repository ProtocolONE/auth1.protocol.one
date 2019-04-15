package manager

import (
	"fmt"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/config"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/models"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/service"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/validator"
	"github.com/ProtocolONE/authone-jwt-verifier-golang"
	"github.com/globalsign/mgo"
	"github.com/globalsign/mgo/bson"
	"github.com/go-redis/redis"
	"github.com/gorilla/sessions"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
	"github.com/ory/hydra-legacy-sdk/swagger"
	"github.com/pkg/errors"
	"gopkg.in/tomb.v2"
	"time"
)

var (
	loginRememberKey   = "login_remember"
	clientIdSessionKey = "oauth_client_id"
	logoutSessionKey   = "oauth_logout_redirect_uri"
	logoutHydraUrl     = "/oauth2/auth/sessions/login/revoke"
)

type OauthManager struct {
	redis                   *redis.Client
	sessionConfig           *config.Session
	hydraConfig             *config.Hydra
	userService             *service.UserService
	userIdentityService     *service.UserIdentityService
	authLogService          *service.AuthLogService
	identityProviderService *service.AppIdentityProviderService
	r                       service.InternalRegistry
}

func NewOauthManager(db *mgo.Session, redis *redis.Client, r service.InternalRegistry, s *config.Session, h *config.Hydra) *OauthManager {
	m := &OauthManager{
		redis:                   redis,
		sessionConfig:           s,
		hydraConfig:             h,
		r:                       r,
		userService:             service.NewUserService(db),
		userIdentityService:     service.NewUserIdentityService(db),
		authLogService:          service.NewAuthLogService(db),
		identityProviderService: service.NewAppIdentityProviderService(),
	}

	return m
}

func (m *OauthManager) CheckAuth(ctx echo.Context, form *models.Oauth2LoginForm) (string, *models.User, []*models.AppIdentityProvider, string, *models.GeneralError) {
	req, _, err := m.r.HydraSDK().GetLoginRequest(form.Challenge)
	if err != nil {
		return "", nil, nil, "", &models.GeneralError{Code: "common", Message: models.ErrorLoginChallenge, Err: errors.Wrap(err, "Unable to get client from login request")}
	}

	app, err := m.r.ApplicationService().Get(bson.ObjectIdHex(req.Client.ClientId))
	if err != nil {
		return "", nil, nil, "", &models.GeneralError{Code: "client_id", Message: models.ErrorClientIdIncorrect, Err: errors.Wrap(err, "Unable to load application")}
	}

	ipc := m.identityProviderService.FindByType(app, models.AppIdentityProviderTypePassword)
	if ipc == nil {
		return req.Client.ClientId, nil, nil, "", &models.GeneralError{Code: "common", Message: models.ErrorUnknownError, Err: errors.New("Unable to get identity providers")}
	}

	sess, err := session.Get(m.sessionConfig.Name, ctx)
	if err != nil {
		return "", nil, nil, "", &models.GeneralError{Code: "common", Message: models.ErrorUnknownError, Err: errors.Wrap(err, "Unable to get session")}
	}
	sess.Values[clientIdSessionKey] = req.Client.ClientId
	if err := sessions.Save(ctx.Request(), ctx.Response()); err != nil {
		return "", nil, nil, "", &models.GeneralError{Code: "common", Message: models.ErrorUnknownError, Err: errors.Wrap(err, "Error saving session")}
	}

	if req.Subject == "" {
		return req.Client.ClientId, nil, ipc, "", nil
	}

	sess.Values[loginRememberKey] = req.Skip == true
	if err := sessions.Save(ctx.Request(), ctx.Response()); err != nil {
		return "", nil, nil, "", &models.GeneralError{Code: "common", Message: models.ErrorUnknownError, Err: errors.Wrap(err, "Error saving session")}
	}

	if req.Skip == true {
		reqACL, _, err := m.r.HydraSDK().AcceptLoginRequest(form.Challenge, swagger.AcceptLoginRequest{Subject: req.Subject})
		if err != nil {
			return req.Client.ClientId, nil, nil, "", &models.GeneralError{Code: "common", Message: models.ErrorPasswordIncorrect, Err: errors.Wrap(err, "Unable to accept login challenge")}
		}

		return req.Client.ClientId, nil, nil, reqACL.RedirectTo, nil
	}

	user, err := m.userService.Get(bson.ObjectIdHex(req.Subject))
	if err != nil {
		return req.Client.ClientId, nil, nil, "", &models.GeneralError{Code: "common", Message: models.ErrorUnknownError, Err: errors.Wrap(err, "Unable to get user")}
	}

	return req.Client.ClientId, user, ipc, "", nil
}

func (m *OauthManager) Auth(ctx echo.Context, form *models.Oauth2LoginSubmitForm) (string, *models.GeneralError) {
	sess, err := session.Get(m.sessionConfig.Name, ctx)
	if err != nil {
		return "", &models.GeneralError{Code: "common", Message: models.ErrorUnknownError, Err: errors.Wrap(err, "Unable to get session")}
	}

	req, _, err := m.r.HydraSDK().GetLoginRequest(form.Challenge)
	if err != nil {
		return "", &models.GeneralError{Code: "common", Message: models.ErrorLoginChallenge, Err: errors.Wrap(err, "Unable to get client from login request")}
	}

	userId := req.Subject
	userIdentity := &models.UserIdentity{}
	if req.Subject == "" || req.Subject != form.PreviousLogin {
		if form.Token != "" {
			if err := m.r.OneTimeTokenService().Use(form.Token, userIdentity); err != nil {
				return "", &models.GeneralError{Code: "common", Message: models.ErrorCannotUseToken, Err: errors.Wrap(err, "Unable to use OneTimeToken")}
			}
		} else {
			app, err := m.r.ApplicationService().Get(bson.ObjectIdHex(req.Client.ClientId))
			if err != nil {
				return "", &models.GeneralError{Code: "client_id", Message: models.ErrorClientIdIncorrect, Err: errors.Wrap(err, "Unable to load application")}
			}

			ipc := m.identityProviderService.FindByTypeAndName(app, models.AppIdentityProviderTypePassword, models.AppIdentityProviderNameDefault)
			if ipc == nil {
				return "", &models.GeneralError{Code: "client_id", Message: models.ErrorClientIdIncorrect, Err: errors.New("Unable to get identity provider")}
			}

			userIdentity, err = m.userIdentityService.Get(app, ipc, form.Email)
			if err != nil {
				return "", &models.GeneralError{Code: "email", Message: models.ErrorLoginIncorrect, Err: errors.Wrap(err, "Unable to get user identity")}
			}

			encryptor := models.NewBcryptEncryptor(&models.CryptConfig{Cost: app.PasswordSettings.BcryptCost})
			if err := encryptor.Compare(userIdentity.Credential, form.Password); err != nil {
				return "", &models.GeneralError{Code: "password", Message: models.ErrorPasswordIncorrect, Err: errors.Wrap(err, "Bad user password")}
			}
		}

		user, err := m.userService.Get(userIdentity.UserID)
		if err != nil {
			return "", &models.GeneralError{Code: "email", Message: models.ErrorLoginIncorrect, Err: errors.Wrap(err, "Unable to get user")}
		}

		user.LoginsCount = user.LoginsCount + 1
		if err := m.userService.Update(user); err != nil {
			return "", &models.GeneralError{Code: "common", Message: models.ErrorUpdateUser, Err: errors.Wrap(err, "Unable to update user")}
		}

		if err := m.authLogService.Add(ctx, user, ""); err != nil {
			return "", &models.GeneralError{Code: "common", Message: models.ErrorAddAuthLog, Err: errors.Wrap(err, "Unable to add auth log")}
		}
		userId = user.ID.Hex()
	} else {
		form.Remember = true
	}

	sess.Values[loginRememberKey] = form.Remember
	if err := sessions.Save(ctx.Request(), ctx.Response()); err != nil {
		return "", &models.GeneralError{Code: "common", Message: models.ErrorUnknownError, Err: errors.Wrap(err, "Error saving session")}
	}

	// TODO: Add MFA cases

	reqACL, _, err := m.r.HydraSDK().AcceptLoginRequest(
		form.Challenge,
		swagger.AcceptLoginRequest{
			Subject:     userId,
			Remember:    form.Remember,
			RememberFor: 0,
		},
	)
	if err != nil {
		return "", &models.GeneralError{Code: "common", Message: models.ErrorPasswordIncorrect, Err: errors.Wrap(err, "Unable to accept login challenge")}
	}

	return reqACL.RedirectTo, nil
}

func (m *OauthManager) Consent(ctx echo.Context, form *models.Oauth2ConsentForm) (string, *models.GeneralError) {
	scopes, err := m.GetScopes()
	// TODO: What scope should be requested to send a person to accept them?
	// For now, we automatically agree with those that the user came with.

	reqGCR, _, err := m.r.HydraSDK().GetConsentRequest(form.Challenge)
	if err != nil {
		return "", &models.GeneralError{Code: "common", Message: models.ErrorUnknownError, Err: errors.Wrap(err, "Unable to get consent challenge")}
	}

	sess, err := session.Get(m.sessionConfig.Name, ctx)
	if err != nil {
		return "", &models.GeneralError{Code: "common", Message: models.ErrorUnknownError, Err: errors.Wrap(err, "Unable to get session")}
	}

	sess.Values[clientIdSessionKey] = reqGCR.Client.ClientId
	if err := sess.Save(ctx.Request(), ctx.Response()); err != nil {
		return "", &models.GeneralError{Code: "common", Message: models.ErrorUnknownError, Err: errors.Wrap(err, "Error saving session")}
	}

	user, err := m.userService.Get(bson.ObjectIdHex(reqGCR.Subject))
	if err != nil {
		return "", &models.GeneralError{Code: "email", Message: models.ErrorLoginIncorrect, Err: errors.Wrap(err, "Unable to get user")}
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

	reqACR, _, err := m.r.HydraSDK().AcceptConsentRequest(form.Challenge, req)
	if err != nil {
		return "", &models.GeneralError{Code: "common", Message: models.ErrorUnknownError, Err: errors.Wrap(err, "Unable to accept consent challenge")}
	}

	return reqACR.RedirectTo, nil
}

func (m *OauthManager) Introspect(ctx echo.Context, form *models.Oauth2IntrospectForm) (*models.Oauth2TokenIntrospection, *models.GeneralError) {
	app, err := m.r.ApplicationService().Get(bson.ObjectIdHex(form.ClientID))
	if err != nil {
		return nil, &models.GeneralError{Code: "client_id", Message: models.ErrorClientIdIncorrect, Err: errors.Wrap(err, "Unable to load application")}
	}

	if app.AuthSecret != form.Secret {
		return nil, &models.GeneralError{Code: "secret", Message: models.ErrorUnknownError, Err: errors.New("Invalid secret key")}
	}

	client, _, err := m.r.HydraSDK().AdminApi.IntrospectOAuth2Token(form.Token, "")
	if err != nil {
		return nil, &models.GeneralError{Code: "common", Message: models.ErrorUnknownError, Err: errors.Wrap(err, "Unable to introspect token")}
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

func (m *OauthManager) SignUp(ctx echo.Context, form *models.Oauth2SignUpForm) (string, *models.GeneralError) {
	sess, err := session.Get(m.sessionConfig.Name, ctx)
	if err != nil {
		return "", &models.GeneralError{Code: "common", Message: models.ErrorUnknownError, Err: errors.Wrap(err, "Unable to get session")}
	}

	sess.Values[loginRememberKey] = form.Remember
	if err := sess.Save(ctx.Request(), ctx.Response()); err != nil {
		return "", &models.GeneralError{Code: "common", Message: models.ErrorUnknownError, Err: errors.Wrap(err, "Error saving session")}
	}
	clientId := sess.Values[clientIdSessionKey].(string)

	app, err := m.r.ApplicationService().Get(bson.ObjectIdHex(clientId))
	if err != nil {
		return "", &models.GeneralError{Code: "client_id", Message: models.ErrorClientIdIncorrect, Err: errors.Wrap(err, "Unable to load application")}
	}
	if false == validator.IsPasswordValid(app, form.Password) {
		return "", &models.GeneralError{Code: "password", Message: models.ErrorPasswordIncorrect, Err: errors.New(models.ErrorPasswordIncorrect)}
	}

	encryptedPassword := ""
	t, _ := tomb.WithContext(ctx.Request().Context())
	t.Go(func() error {
		encryptor := models.NewBcryptEncryptor(&models.CryptConfig{Cost: app.PasswordSettings.BcryptCost})
		encryptedPassword, err = encryptor.Digest(form.Password)
		return err
	})

	req, _, err := m.r.HydraSDK().GetLoginRequest(form.Challenge)
	if err != nil {
		return "", &models.GeneralError{Code: "common", Message: models.ErrorLoginChallenge, Err: errors.Wrap(err, "Unable to get client from login request")}
	}
	if req.Client.ClientId != clientId {
		return "", &models.GeneralError{Code: "common", Message: models.ErrorClientIdIncorrect, Err: errors.Wrap(err, "Client ID is incorrect")}
	}

	ipc := m.identityProviderService.FindByTypeAndName(app, models.AppIdentityProviderTypePassword, models.AppIdentityProviderNameDefault)
	if ipc == nil {
		return "", &models.GeneralError{Code: "client_id", Message: models.ErrorProviderIdIncorrect, Err: errors.New("Unable to get identity provider")}
	}

	userIdentity, err := m.userIdentityService.Get(app, ipc, form.Email)
	if err != nil && err != mgo.ErrNotFound {
		return "", &models.GeneralError{Code: "email", Message: models.ErrorLoginIncorrect, Err: errors.Wrap(err, "Unable to get user with identity for application")}
	}

	if err := t.Wait(); err != nil {
		return "", &models.GeneralError{Code: "password", Message: models.ErrorCryptPassword, Err: errors.Wrap(err, "Unable to crypt password")}
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
		return "", &models.GeneralError{Code: "common", Message: models.ErrorCreateUser, Err: errors.Wrap(err, "Unable to create user")}
	}

	userIdentity = &models.UserIdentity{
		ID:                 bson.NewObjectId(),
		UserID:             user.ID,
		ApplicationID:      app.ID,
		ExternalID:         form.Email,
		IdentityProviderID: ipc.ID,
		Credential:         encryptedPassword,
		Email:              form.Email,
		CreatedAt:          time.Now(),
		UpdatedAt:          time.Now(),
	}
	if err := m.userIdentityService.Create(userIdentity); err != nil {
		return "", &models.GeneralError{Code: "common", Message: models.ErrorCreateUserIdentity, Err: errors.Wrap(err, "Unable to create user identity")}
	}

	if err := m.authLogService.Add(ctx, user, ""); err != nil {
		return "", &models.GeneralError{Code: "common", Message: models.ErrorAddAuthLog, Err: errors.Wrap(err, "Unable to add auth log")}
	}

	reqACL, _, err := m.r.HydraSDK().AcceptLoginRequest(form.Challenge, swagger.AcceptLoginRequest{Subject: user.ID.Hex()})
	if err != nil {
		return "", &models.GeneralError{Code: "common", Message: models.ErrorUnknownError, Err: errors.Wrap(err, "Unable to accept login challenge")}
	}

	return reqACL.RedirectTo, nil
}

func (m *OauthManager) CallBack(ctx echo.Context, form *models.Oauth2CallBackForm) (*models.Oauth2CallBackResponse, *models.GeneralError) {
	sess, err := session.Get(m.sessionConfig.Name, ctx)
	if err != nil {
		return &models.Oauth2CallBackResponse{
				Success:      false,
				ErrorMessage: `unknown_client_id`,
			}, &models.GeneralError{
				Code:    "common",
				Message: "Unable to get session",
				Err:     errors.Wrap(err, "Unable to get session"),
			}
	}
	clientId := sess.Values[clientIdSessionKey].(string)
	if clientId == "" {
		return &models.Oauth2CallBackResponse{
				Success:      false,
				ErrorMessage: `unknown_client_id`,
			}, &models.GeneralError{
				Code:    "common",
				Message: "Unable to get client id from session",
				Err:     errors.New("Unable to get client id from session"),
			}
	}

	app, err := m.r.ApplicationService().Get(bson.ObjectIdHex(clientId))
	if err != nil {
		return &models.Oauth2CallBackResponse{
				Success:      false,
				ErrorMessage: `invalid_client_id`,
			}, &models.GeneralError{
				Code:    "client_id",
				Message: models.ErrorClientIdIncorrect,
				Err:     errors.Wrap(err, "Unable to load application"),
			}
	}

	settings := jwtverifier.Config{
		ClientID:     clientId,
		ClientSecret: app.AuthSecret,
		RedirectURL:  fmt.Sprintf("%s://%s/oauth2/callback", ctx.Scheme(), ctx.Request().Host),
		Issuer:       m.hydraConfig.PublicURL,
	}
	jwtv := jwtverifier.NewJwtVerifier(settings)
	tokens, err := jwtv.Exchange(ctx.Request().Context(), form.Code)
	if err != nil {
		return &models.Oauth2CallBackResponse{
				Success:      false,
				ErrorMessage: `unable_exchange_code`,
			}, &models.GeneralError{
				Code:    "common",
				Message: models.ErrorUnknownError,
				Err:     errors.Wrap(err, "Unable to exchange code to token"),
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
	}, nil
}

func (m *OauthManager) Logout(ctx echo.Context, form *models.Oauth2LogoutForm) (string, *models.GeneralError) {
	sess, err := session.Get(m.sessionConfig.Name, ctx)
	if err != nil {
		return "", &models.GeneralError{Code: "common", Message: models.ErrorUnknownError, Err: errors.Wrap(err, "Unable to get session")}
	}

	logoutRedirectUri := sess.Values[logoutSessionKey]
	if form.RedirectUri == "" {
		form.RedirectUri = "auth1"
	}
	if logoutRedirectUri == "" || logoutRedirectUri == nil {
		sess.Values[logoutSessionKey] = form.RedirectUri
		if err := sess.Save(ctx.Request(), ctx.Response()); err != nil {
			return "", &models.GeneralError{Code: "common", Message: models.ErrorUnknownError, Err: errors.Wrap(err, "Error saving session")}
		}
		return logoutHydraUrl, nil
	}

	sess.Values[logoutSessionKey] = ""
	if err := sess.Save(ctx.Request(), ctx.Response()); err != nil {
		return "", &models.GeneralError{Code: "common", Message: models.ErrorUnknownError, Err: errors.Wrap(err, "Error saving session")}
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
