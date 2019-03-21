package manager

import (
	"auth-one-api/pkg/database"
	"auth-one-api/pkg/helper"
	"auth-one-api/pkg/models"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/ProtocolONE/authone-jwt-verifier-golang"
	"github.com/globalsign/mgo/bson"
	"github.com/go-redis/redis"
	"github.com/gorilla/sessions"
	"github.com/labstack/echo"
	"go.uber.org/zap"
	"net/http"
	"strings"
	"time"
)

var (
	SocialAccountCanLink = "link"
	SocialAccountSuccess = "success"
	SocialAccountError   = "error"
)

type LoginManager struct {
	logger                  *zap.Logger
	redis                   *redis.Client
	session                 *sessions.Session
	appService              *models.ApplicationService
	userService             *models.UserService
	userIdentityService     *models.UserIdentityService
	mfaService              *models.MfaService
	authLogService          *models.AuthLogService
	identityProviderService *models.AppIdentityProviderService
}

func NewLoginManager(logger *zap.Logger, h *database.Handler, redis *redis.Client, session *sessions.Session) *LoginManager {
	m := &LoginManager{
		logger:              logger,
		redis:               redis,
		session:             session,
		appService:          models.NewApplicationService(h),
		userService:         models.NewUserService(h),
		userIdentityService: models.NewUserIdentityService(h),
		mfaService:          models.NewMfaService(h),
		authLogService:      models.NewAuthLogService(h),
	}

	return m
}

func (m *LoginManager) Authorize(ctx echo.Context, form *models.AuthorizeForm) (string, models.ErrorInterface) {
	if form.Connection == `incorrect` {
		return "", &models.CommonError{Message: models.ErrorConnectionIncorrect}
	}

	a, err := m.appService.Get(bson.ObjectIdHex(form.ClientID))
	if err != nil {
		m.logger.Error(
			"Unable to get application",
			zap.Object("AuthorizeForm", form),
			zap.Error(err),
		)

		return "", &models.CommonError{Code: `client_id`, Message: models.ErrorClientIdIncorrect}
	}

	uic, err := m.appService.GetUserIdentityConnection(a, models.AppIdentityProviderTypeSocial, form.Connection)
	if err != nil {
		m.logger.Error(
			"Unable to load user identity settings for application",
			zap.Object("AuthorizeForm", form),
			zap.String("Provider", models.AppIdentityProviderTypeSocial),
			zap.Error(err),
		)

		return "", &models.CommonError{Code: `common`, Message: models.ErrorUnableValidatePassword}
	}

	u, err := uic.GetAuthUrl(ctx, form)
	if err != nil {
		m.logger.Error(
			"Unable to get auth url from authorize form",
			zap.Object("AuthorizeForm", form),
			zap.Error(err),
		)

		return "", &models.CommonError{Code: `common`, Message: models.ErrorUnknownError}
	}
	fmt.Print(u)
	return u, nil
}

func (m *LoginManager) AuthorizeResult(ctx echo.Context, form *models.AuthorizeResultForm) (token *models.AuthorizeResultResponse, error models.ErrorInterface) {
	authForm := &models.AuthorizeForm{}

	s, err := base64.StdEncoding.DecodeString(form.State)
	if err != nil {
		m.logger.Error(
			"Unable to decode state param",
			zap.Object("AuthorizeResultForm", form),
			zap.Error(err),
		)

		return nil, &models.CommonError{Code: `common`, Message: models.ErrorUnknownError}
	}

	if err := json.Unmarshal([]byte(s), authForm); err != nil {
		m.logger.Error(
			"Unable to unmarshal auth form",
			zap.Object("AuthorizeResultForm", form),
			zap.Error(err),
		)

		return nil, &models.CommonError{Code: `common`, Message: models.ErrorUnknownError}
	}

	app, err := m.appService.Get(bson.ObjectIdHex(authForm.ClientID))
	if err != nil {
		m.logger.Error(
			"Unable to get application service for client",
			zap.Object("AuthorizeForm", authForm),
			zap.Error(err),
		)

		return nil, &models.CommonError{Code: `client_id`, Message: models.ErrorClientIdIncorrect}
	}

	uic, err := m.appService.GetUserIdentityConnection(app, models.AppIdentityProviderTypeSocial, authForm.Connection)
	if err != nil {
		m.logger.Error(
			"Unable to load user identity settings for application",
			zap.Object("AuthorizeForm", authForm),
			zap.Error(err),
		)

		return nil, &models.CommonError{Code: `common`, Message: models.ErrorConnectionIncorrect}
	}

	cp, err := uic.GetClientProfile(ctx)
	if err != nil || cp.ID == "" {
		m.logger.Error(
			"Unable to load identity profile for application",
			zap.Object("AuthorizeForm", authForm),
			zap.Error(err),
		)

		return nil, &models.CommonError{Code: `common`, Message: models.ErrorGetSocialData}
	}

	ipc, err := m.identityProviderService.FindByTypeAndName(app, models.AppIdentityProviderTypeSocial, authForm.Connection)
	if err != nil {
		m.logger.Warn(
			"Unable to get identity provider",
			zap.Object("AuthorizeForm", form),
			zap.Error(err),
		)
	}

	userIdentity, err := m.userIdentityService.Get(app, ipc, cp.ID)
	if userIdentity != nil {
		user, err := m.userService.Get(userIdentity.UserID)
		if err != nil {
			m.logger.Error(
				"Unable to get user identity by email for application",
				zap.Object("UserIdentitySocial", cp),
				zap.Object("AuthorizeForm", authForm),
				zap.Error(err),
			)

			return nil, &models.CommonError{Code: `common`, Message: models.ErrorLoginIncorrect}
		}

		t, err := helper.CreateAuthToken(ctx, m.appService, user)
		if err != nil {
			m.logger.Error(
				"Unable to create user auth token for application",
				zap.Object("User", user),
				zap.Object("Application", app),
				zap.Error(err),
			)

			return nil, &models.CommonError{Code: `common`, Message: err.Error()}
		}

		if err := m.authLogService.Add(ctx, user, t.RefreshToken); err != nil {
			m.logger.Error(
				"Unable to log authorization for user",
				zap.Object("User", user),
				zap.Error(err),
			)

			return nil, &models.CommonError{Code: `common`, Message: models.ErrorAddAuthLog}
		}

		cs, err := m.appService.LoadSessionSettings()
		if err != nil {
			m.logger.Error(
				"Unable to load session settings for application",
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

		url, err := helper.PrepareRedirectUrl(authForm.RedirectUri, ott)
		if err != nil {
			m.logger.Error(
				"Unable to create redirect url",
				zap.Object("LoginForm", form),
				zap.Object("OneTimeToken", ott),
				zap.Error(err),
			)
			return nil, &models.CommonError{Code: `common`, Message: models.ErrorCannotCreateToken}
		}

		return &models.AuthorizeResultResponse{
			Result:  SocialAccountSuccess,
			Payload: map[string]interface{}{"url": url},
		}, nil
	}

	ipcDB, err := m.identityProviderService.FindByTypeAndName(app, models.AppIdentityProviderTypePassword, models.AppIdentityProviderNameDefault)
	if err != nil {
		m.logger.Warn(
			"Unable to get identity provider",
			zap.Object("AuthorizeResultForm", form),
			zap.Error(err),
		)
	}

	userIdentity, err = m.userIdentityService.Get(app, ipcDB, cp.Email)
	if userIdentity != nil {
		ss, err := m.appService.LoadSocialSettings()
		if err != nil {
			m.logger.Error(
				"Unable to load social settings for application",
				zap.Object("AuthorizeForm", authForm),
				zap.Object("UserIdentitySocial", cp),
				zap.Object("Application", app),
				zap.Error(err),
			)

			return nil, &models.CommonError{Code: `common`, Message: models.ErrorGetSocialSettings}
		}

		ottSettings := &models.OneTimeTokenSettings{
			Length: ss.LinkedTokenLength,
			TTL:    ss.LinkedTTL,
		}
		os := models.NewOneTimeTokenService(m.redis, ottSettings)
		ott, err := os.Create(&models.UserIdentity{
			ID:                 bson.NewObjectId(),
			UserID:             userIdentity.UserID,
			ApplicationID:      app.ID,
			IdentityProviderID: ipc.ID,
			ExternalID:         cp.ID,
			Credential:         cp.Token,
			Email:              cp.Email,
			Name:               cp.Name,
			CreatedAt:          time.Now(),
			UpdatedAt:          time.Now(),
		})

		if err != nil {
			m.logger.Error(
				"Unable to create one-time token for application",
				zap.Object("AuthorizeForm", authForm),
				zap.Object("UserIdentitySocial", cp),
				zap.Object("Application", app),
				zap.Error(err),
			)

			return nil, &models.CommonError{Code: `common`, Message: models.ErrorCannotCreateToken}
		}

		return &models.AuthorizeResultResponse{
			Result:  SocialAccountCanLink,
			Payload: map[string]interface{}{"token": ott.Token, "email": cp.Email},
		}, nil
	}

	user := &models.User{
		ID:            bson.NewObjectId(),
		AppID:         app.ID,
		Email:         cp.Email,
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
			zap.Object("AuthorizeForm", authForm),
			zap.Object("UserIdentitySocial", cp),
			zap.Object("Application", app),
			zap.Error(err),
		)

		return nil, &models.CommonError{Code: `common`, Message: models.ErrorCreateUser}
	}

	userIdentity = &models.UserIdentity{
		ID:                 bson.NewObjectId(),
		UserID:             user.ID,
		ApplicationID:      app.ID,
		IdentityProviderID: ipc.ID,
		Email:              cp.Email,
		ExternalID:         cp.ID,
		Name:               cp.Name,
		CreatedAt:          time.Now(),
		UpdatedAt:          time.Now(),
		Credential:         cp.Token,
	}

	if err := m.userIdentityService.Create(userIdentity); err != nil {
		m.logger.Error(
			"Unable to create user identity for an application",
			zap.Object("AuthorizeForm", authForm),
			zap.Object("UserIdentitySocial", cp),
			zap.Object("Application", app),
			zap.Error(err),
		)

		return nil, &models.CommonError{Code: `common`, Message: models.ErrorCreateUserIdentity}
	}

	t, err := helper.CreateAuthToken(ctx, m.appService, user)
	if err != nil {
		m.logger.Error(
			"Unable to create user [%s] auth token for application[%s] with error: %s",
			zap.Object("AuthorizeForm", authForm),
			zap.Object("UserIdentitySocial", cp),
			zap.Object("Application", app),
			zap.Error(err),
		)

		return nil, &models.CommonError{Code: `common`, Message: err.Error()}
	}

	if err := m.authLogService.Add(ctx, user, t.RefreshToken); err != nil {
		m.logger.Error(
			"Unable to log auth for user",
			zap.Object("User", user),
		)

		return nil, &models.CommonError{Code: `common`, Message: models.ErrorAddAuthLog}
	}

	cs, err := m.appService.LoadSessionSettings()
	if err != nil {
		m.logger.Error(
			"Unable to load session settings for application",
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

	url, err := helper.PrepareRedirectUrl(authForm.RedirectUri, ott)
	if err != nil {
		m.logger.Error(
			"Unable to create redirect url",
			zap.Object("LoginForm", form),
			zap.Object("OneTimeToken", ott),
			zap.Error(err),
		)
		return nil, &models.CommonError{Code: `common`, Message: models.ErrorCannotCreateToken}
	}

	return &models.AuthorizeResultResponse{
		Result:  SocialAccountSuccess,
		Payload: map[string]interface{}{"url": url},
	}, nil
}

func (m *LoginManager) AuthorizeLink(ctx echo.Context, form *models.AuthorizeLinkForm) (token *models.AuthToken, error models.ErrorInterface) {
	app, err := m.appService.Get(bson.ObjectIdHex(form.ClientID))
	if err != nil {
		m.logger.Error(
			"Unable to get application",
			zap.Object("AuthorizeLinkForm", form),
			zap.Error(err),
		)

		return nil, &models.CommonError{Code: `client_id`, Message: models.ErrorClientIdIncorrect}
	}

	ottSettings := &models.OneTimeTokenSettings{}
	os := models.NewOneTimeTokenService(m.redis, ottSettings)
	sl := &models.UserIdentity{}
	if err := os.Get(form.Code, sl); err != nil {
		m.logger.Error(
			"Unable to use token for application",
			zap.Object("AuthorizeLinkForm", form),
			zap.Error(err),
		)

		return nil, &models.CommonError{Code: `common`, Message: models.ErrorCannotUseToken}
	}

	user := &models.User{
		ID:            bson.NewObjectId(),
		AppID:         app.ID,
		Email:         sl.Email,
		EmailVerified: false,
		Blocked:       false,
		LastIp:        ctx.RealIP(),
		LastLogin:     time.Now(),
		LoginsCount:   1,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	switch form.Action {
	case "link":
		ps, err := m.appService.GetPasswordSettings(app)
		if err != nil {
			m.logger.Error(
				"Unable to load password settings for application",
				zap.Object("AuthorizeLinkForm", form),
				zap.Error(err),
			)

			return nil, &models.CommonError{Code: `common`, Message: models.ErrorUnableValidatePassword}
		}
		if false == ps.IsValid(form.Password) {
			return nil, &models.CommonError{Code: `password`, Message: models.ErrorPasswordIncorrect}
		}

		ipc, err := m.identityProviderService.FindByTypeAndName(app, models.AppIdentityProviderTypePassword, models.AppIdentityProviderNameDefault)
		if err != nil {
			m.logger.Warn(
				"Unable to get identity provider",
				zap.Object("AuthorizeLinkForm", form),
				zap.Error(err),
			)
		}

		userIdentity, err := m.userIdentityService.Get(app, ipc, user.Email)

		be := models.NewBcryptEncryptor(&models.CryptConfig{Cost: ps.BcryptCost})

		err = be.Compare(userIdentity.Credential, form.Password)
		if err != nil {
			m.logger.Warn(
				"Unable to crypt password for application",
				zap.Object("AuthorizeLinkForm", form),
				zap.Error(err),
			)

			return nil, &models.CommonError{Code: `password`, Message: models.ErrorPasswordIncorrect}
		}

		mfa, err := m.mfaService.GetUserProviders(user)
		if err != nil {
			m.logger.Error(
				"Unable to load MFA providers for user",
				zap.Object("User", user),
				zap.Object("Application", app),
				zap.Error(err),
			)

			return nil, &models.CommonError{Code: `common`, Message: models.ErrorUnknownError}
		}

		if len(mfa) > 0 {
			ottSettings := &models.OneTimeTokenSettings{
				Length: 64,
				TTL:    3600,
			}
			os := models.NewOneTimeTokenService(m.redis, ottSettings)
			ott, err := os.Create(&models.UserMfaToken{
				UserIdentity: userIdentity,
				MfaProvider:  mfa[0],
			})
			if err != nil {
				m.logger.Error(
					"Unable to create one-time token for application",
					zap.Object("UserIdentity", userIdentity),
					zap.Error(err),
				)

				return nil, &models.CommonError{Code: `common`, Message: models.ErrorCannotCreateToken}
			}

			return nil, &models.MFARequiredError{HttpCode: http.StatusForbidden, Message: ott.Token}
		}

		user, err = m.userService.Get(userIdentity.UserID)
		if err != nil {
			m.logger.Error(
				"Unable to get user",
				zap.Object("UserIdentity", userIdentity),
				zap.Error(err),
			)

			return nil, &models.CommonError{Code: `email`, Message: models.ErrorLoginIncorrect}
		}
	case "new":
		if err := m.userService.Create(user); err != nil {
			m.logger.Error(
				"Unable to create user with identity",
				zap.Object("UserIdentity", sl),
				zap.Error(err),
			)

			return nil, &models.CommonError{Code: `common`, Message: models.ErrorCreateUser}
		}
		sl.UserID = user.ID
	default:
		m.logger.Error(
			"Unknown action type for social link",
			zap.Object("AuthorizeLinkForm", form),
			zap.Error(err),
		)

		return nil, &models.CommonError{Code: `common`, Message: models.ErrorUnknownError}
	}

	if err := m.userIdentityService.Create(sl); err != nil {
		m.logger.Error(
			"Unable to create user identity for application",
			zap.Object("UserIdentity", sl),
			zap.Error(err),
		)

		return nil, &models.CommonError{Code: `common`, Message: models.ErrorCreateUserIdentity}
	}

	t, err := helper.CreateAuthToken(ctx, m.appService, user)
	if err != nil {
		m.logger.Error(
			"Unable to create user auth token for application",
			zap.Object("User", user),
			zap.Object("Application", app),
			zap.Error(err),
		)

		return nil, &models.CommonError{Code: `common`, Message: err.Error()}
	}

	if err := m.authLogService.Add(ctx, user, t.RefreshToken); err != nil {
		m.logger.Error(
			"Unable to log authorization for user",
			zap.Object("User", user),
			zap.Error(err),
		)

		return nil, &models.CommonError{Code: `common`, Message: models.ErrorAddAuthLog}
	}

	cs, err := m.appService.LoadSessionSettings()
	if err != nil {
		m.logger.Error(
			"Unable to load session settings for application",
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

func (m *LoginManager) LoginByOTT(form *models.OneTimeTokenForm) (token *models.AuthToken, error models.ErrorInterface) {
	ottSettings := &models.OneTimeTokenSettings{}
	os := models.NewOneTimeTokenService(m.redis, ottSettings)
	token = &models.AuthToken{}

	if err := os.Get(form.Token, token); err != nil {
		m.logger.Error(
			"Unable to use auth token for application",
			zap.Object("OneTimeTokenForm", form),
			zap.Error(err),
		)

		return nil, &models.CommonError{Code: `common`, Message: models.ErrorCannotUseToken}
	}

	return token, nil
}

func (m *LoginManager) CreateAuthUrl(ctx echo.Context, form *models.LoginPageForm) (string, error) {
	scopes := []string{"openid"}
	if form.Scopes != "" {
		scopes = strings.Split(form.Scopes, " ")
	}

	if form.RedirectUri == "" {
		form.RedirectUri = fmt.Sprintf("%s://%s/oauth2/callback", ctx.Scheme(), ctx.Request().Host)
		m.session.Values[clientIdSessionKey] = form.ClientID
		if err := sessions.Save(ctx.Request(), ctx.Response()); err != nil {
			m.logger.Error("Error saving session", zap.Error(err))
			return "", err
		}
	}

	settings := jwtverifier.Config{
		ClientID:     form.ClientID,
		ClientSecret: "",
		Scopes:       scopes,
		RedirectURL:  form.RedirectUri,
		Issuer:       fmt.Sprintf("%s://%s", ctx.Scheme(), ctx.Request().Host),
	}
	jwtv := jwtverifier.NewJwtVerifier(settings)

	return jwtv.CreateAuthUrl(form.State), nil
}
