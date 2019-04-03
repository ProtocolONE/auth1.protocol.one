package manager

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/helper"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/models"
	"github.com/ProtocolONE/authone-jwt-verifier-golang"
	"github.com/globalsign/mgo"
	"github.com/globalsign/mgo/bson"
	"github.com/go-redis/redis"
	"github.com/labstack/echo/v4"
	"github.com/ory/hydra/sdk/go/hydra"
	"github.com/ory/hydra/sdk/go/hydra/swagger"
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
	redis                   *redis.Client
	appService              *models.ApplicationService
	userService             *models.UserService
	userIdentityService     *models.UserIdentityService
	mfaService              *models.MfaService
	authLogService          *models.AuthLogService
	identityProviderService *models.AppIdentityProviderService
	hydra                   *hydra.CodeGenSDK
}

func NewLoginManager(h *mgo.Session, redis *redis.Client, hydra *hydra.CodeGenSDK) *LoginManager {
	m := &LoginManager{
		redis:                   redis,
		hydra:                   hydra,
		appService:              models.NewApplicationService(h),
		userService:             models.NewUserService(h),
		userIdentityService:     models.NewUserIdentityService(h),
		mfaService:              models.NewMfaService(h),
		authLogService:          models.NewAuthLogService(h),
		identityProviderService: models.NewAppIdentityProviderService(h),
	}

	return m
}

func (m *LoginManager) Authorize(ctx echo.Context, form *models.AuthorizeForm) (string, models.ErrorInterface) {
	if form.Connection == `incorrect` {
		return "", &models.CommonError{Message: models.ErrorConnectionIncorrect}
	}

	app, err := m.appService.Get(bson.ObjectIdHex(form.ClientID))
	if err != nil {
		zap.L().Error(
			"Unable to get application",
			zap.Object("AuthorizeForm", form),
			zap.Error(err),
			zap.String(echo.HeaderXRequestID, helper.GetRequestIdFromHeader(ctx)),
		)

		return "", &models.CommonError{Code: `client_id`, Message: models.ErrorClientIdIncorrect}
	}

	ip, err := m.identityProviderService.FindByTypeAndName(app, models.AppIdentityProviderTypeSocial, form.Connection)
	if err != nil {
		zap.L().Error(
			"Unable to load user identity settings for application",
			zap.Object("AuthorizeForm", form),
			zap.String("Provider", models.AppIdentityProviderTypeSocial),
			zap.Error(err),
			zap.String(echo.HeaderXRequestID, helper.GetRequestIdFromHeader(ctx)),
		)

		return "", &models.CommonError{Code: `common`, Message: models.ErrorUnableValidatePassword}
	}

	u, err := ip.GetAuthUrl(ctx, form)
	if err != nil {
		zap.L().Error(
			"Unable to get auth url from authorize form",
			zap.Object("AuthorizeForm", form),
			zap.Error(err),
			zap.String(echo.HeaderXRequestID, helper.GetRequestIdFromHeader(ctx)),
		)

		return "", &models.CommonError{Code: `common`, Message: models.ErrorUnknownError}
	}

	return u, nil
}

func (m *LoginManager) AuthorizeResult(ctx echo.Context, form *models.AuthorizeResultForm) (token *models.AuthorizeResultResponse, error models.ErrorInterface) {
	authForm := &models.AuthorizeForm{}

	s, err := base64.StdEncoding.DecodeString(form.State)
	if err != nil {
		zap.L().Error(
			"Unable to decode state param",
			zap.Object("AuthorizeResultForm", form),
			zap.Error(err),
			zap.String(echo.HeaderXRequestID, helper.GetRequestIdFromHeader(ctx)),
		)

		return nil, &models.CommonError{Code: `common`, Message: models.ErrorUnknownError}
	}

	if err := json.Unmarshal([]byte(s), authForm); err != nil {
		zap.L().Error(
			"Unable to unmarshal auth form",
			zap.Object("AuthorizeResultForm", form),
			zap.Error(err),
			zap.String(echo.HeaderXRequestID, helper.GetRequestIdFromHeader(ctx)),
		)

		return nil, &models.CommonError{Code: `common`, Message: models.ErrorUnknownError}
	}

	app, err := m.appService.Get(bson.ObjectIdHex(authForm.ClientID))
	if err != nil {
		zap.L().Error(
			"Unable to get application service for client",
			zap.Object("AuthorizeForm", authForm),
			zap.Error(err),
			zap.String(echo.HeaderXRequestID, helper.GetRequestIdFromHeader(ctx)),
		)

		return nil, &models.CommonError{Code: `client_id`, Message: models.ErrorClientIdIncorrect}
	}

	ip, err := m.identityProviderService.FindByTypeAndName(app, models.AppIdentityProviderTypeSocial, authForm.Connection)
	if err != nil {
		zap.L().Error(
			"Unable to load user identity settings for application",
			zap.Object("AuthorizeForm", authForm),
			zap.Error(err),
			zap.String(echo.HeaderXRequestID, helper.GetRequestIdFromHeader(ctx)),
		)

		return nil, &models.CommonError{Code: `common`, Message: models.ErrorConnectionIncorrect}
	}

	cp, err := m.identityProviderService.GetSocialProfile(ctx, ip)
	if err != nil || cp.ID == "" {
		zap.L().Error(
			"Unable to load identity profile for application",
			zap.Object("AuthorizeForm", authForm),
			zap.Error(err),
			zap.String(echo.HeaderXRequestID, helper.GetRequestIdFromHeader(ctx)),
		)

		return nil, &models.CommonError{Code: `common`, Message: models.ErrorGetSocialData}
	}

	userIdentity, err := m.userIdentityService.Get(app, ip, cp.ID)
	if userIdentity != nil && err != mgo.ErrNotFound {
		user, err := m.userService.Get(userIdentity.UserID)
		if err != nil {
			zap.L().Error(
				"Unable to get user identity by email for application",
				zap.Object("UserIdentitySocial", cp),
				zap.Object("AuthorizeForm", authForm),
				zap.Error(err),
				zap.String(echo.HeaderXRequestID, helper.GetRequestIdFromHeader(ctx)),
			)

			return nil, &models.CommonError{Code: `common`, Message: models.ErrorLoginIncorrect}
		}

		if err := m.authLogService.Add(ctx, user, ""); err != nil {
			zap.L().Error(
				"Unable to log authorization for user",
				zap.Object("User", user),
				zap.Error(err),
				zap.String(echo.HeaderXRequestID, helper.GetRequestIdFromHeader(ctx)),
			)

			return nil, &models.CommonError{Code: `common`, Message: models.ErrorAddAuthLog}
		}

		ottSettings := &models.OneTimeTokenSettings{
			Length: 64,
			TTL:    3600,
		}
		os := models.NewOneTimeTokenService(m.redis, ottSettings)
		ott, err := os.Create(userIdentity)
		if err != nil {
			zap.L().Error(
				"Unable to create one-time token for application",
				zap.Object("LoginForm", form),
				zap.Object("User", user),
				zap.Object("Application", app),
				zap.Error(err),
				zap.String(echo.HeaderXRequestID, helper.GetRequestIdFromHeader(ctx)),
			)

			return nil, &models.CommonError{Code: `common`, Message: models.ErrorCannotCreateToken}
		}

		return &models.AuthorizeResultResponse{
			Result:  SocialAccountSuccess,
			Payload: map[string]interface{}{"token": ott.Token},
		}, nil
	}

	if cp.Email != "" {
		ipPass, err := m.identityProviderService.FindByTypeAndName(app, models.AppIdentityProviderTypePassword, models.AppIdentityProviderNameDefault)
		if err != nil {
			zap.L().Error(
				"Unable to load user identity settings for application",
				zap.Object("AuthorizeForm", authForm),
				zap.Error(err),
				zap.String(echo.HeaderXRequestID, helper.GetRequestIdFromHeader(ctx)),
			)

			return nil, &models.CommonError{Code: `common`, Message: models.ErrorConnectionIncorrect}
		}

		userIdentity, err := m.userIdentityService.Get(app, ipPass, cp.Email)
		if err != nil && err != mgo.ErrNotFound {
			zap.L().Warn(
				"Unable to get user identity",
				zap.Object("AuthorizeResultForm", form),
				zap.Error(err),
				zap.String(echo.HeaderXRequestID, helper.GetRequestIdFromHeader(ctx)),
			)
		}

		if userIdentity != nil {
			ss, err := m.appService.LoadSocialSettings()
			if err != nil {
				zap.L().Error(
					"Unable to load social settings for application",
					zap.Object("AuthorizeForm", authForm),
					zap.Object("UserIdentitySocial", cp),
					zap.Object("Application", app),
					zap.Error(err),
					zap.String(echo.HeaderXRequestID, helper.GetRequestIdFromHeader(ctx)),
				)

				return nil, &models.CommonError{Code: `common`, Message: models.ErrorGetSocialSettings}
			}

			ottSettings := &models.OneTimeTokenSettings{
				Length: ss.LinkedTokenLength,
				TTL:    ss.LinkedTTL,
			}
			os := models.NewOneTimeTokenService(m.redis, ottSettings)
			userIdentity.IdentityProviderID = ip.ID
			userIdentity.ExternalID = cp.ID
			userIdentity.Email = cp.Email
			ott, err := os.Create(userIdentity)

			if err != nil {
				zap.L().Error(
					"Unable to create one-time token for application",
					zap.Object("AuthorizeForm", authForm),
					zap.Object("UserIdentitySocial", cp),
					zap.Object("Application", app),
					zap.Error(err),
					zap.String(echo.HeaderXRequestID, helper.GetRequestIdFromHeader(ctx)),
				)

				return nil, &models.CommonError{Code: `common`, Message: models.ErrorCannotCreateToken}
			}

			return &models.AuthorizeResultResponse{
				Result:  SocialAccountCanLink,
				Payload: map[string]interface{}{"token": ott.Token, "email": cp.Email},
			}, nil
		}
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
		zap.L().Error(
			"Unable to create user with identity for application",
			zap.Object("AuthorizeForm", authForm),
			zap.Object("UserIdentitySocial", cp),
			zap.Object("Application", app),
			zap.Error(err),
			zap.String(echo.HeaderXRequestID, helper.GetRequestIdFromHeader(ctx)),
		)

		return nil, &models.CommonError{Code: `common`, Message: models.ErrorCreateUser}
	}

	userIdentity = &models.UserIdentity{
		ID:                 bson.NewObjectId(),
		UserID:             user.ID,
		ApplicationID:      app.ID,
		IdentityProviderID: ip.ID,
		Email:              cp.Email,
		ExternalID:         cp.ID,
		Name:               cp.Name,
		CreatedAt:          time.Now(),
		UpdatedAt:          time.Now(),
		Credential:         cp.Token,
	}
	if err := m.userIdentityService.Create(userIdentity); err != nil {
		zap.L().Error(
			"Unable to create user identity for an application",
			zap.Object("AuthorizeForm", authForm),
			zap.Object("UserIdentitySocial", cp),
			zap.Object("Application", app),
			zap.Error(err),
			zap.String(echo.HeaderXRequestID, helper.GetRequestIdFromHeader(ctx)),
		)

		return nil, &models.CommonError{Code: `common`, Message: models.ErrorCreateUserIdentity}
	}

	if err := m.authLogService.Add(ctx, user, ""); err != nil {
		zap.L().Error(
			"Unable to log auth for user",
			zap.Object("User", user),
			zap.String(echo.HeaderXRequestID, helper.GetRequestIdFromHeader(ctx)),
		)

		return nil, &models.CommonError{Code: `common`, Message: models.ErrorAddAuthLog}
	}

	ottSettings := &models.OneTimeTokenSettings{
		Length: 64,
		TTL:    3600,
	}
	os := models.NewOneTimeTokenService(m.redis, ottSettings)
	ott, err := os.Create(&userIdentity)
	if err != nil {
		zap.L().Error(
			"Unable to create one-time token for application",
			zap.Object("LoginForm", form),
			zap.Object("User", user),
			zap.Object("Application", app),
			zap.Error(err),
			zap.String(echo.HeaderXRequestID, helper.GetRequestIdFromHeader(ctx)),
		)

		return nil, &models.CommonError{Code: `common`, Message: models.ErrorCannotCreateToken}
	}

	return &models.AuthorizeResultResponse{
		Result:  SocialAccountSuccess,
		Payload: map[string]interface{}{"token": ott.Token},
	}, nil
}

func (m *LoginManager) AuthorizeLink(ctx echo.Context, form *models.AuthorizeLinkForm) (string, models.ErrorInterface) {
	app, err := m.appService.Get(bson.ObjectIdHex(form.ClientID))
	if err != nil {
		zap.L().Error(
			"Unable to get application",
			zap.Object("AuthorizeLinkForm", form),
			zap.Error(err),
			zap.String(echo.HeaderXRequestID, helper.GetRequestIdFromHeader(ctx)),
		)

		return "", &models.CommonError{Code: `client_id`, Message: models.ErrorClientIdIncorrect}
	}

	ottSettings := &models.OneTimeTokenSettings{}
	os := models.NewOneTimeTokenService(m.redis, ottSettings)
	storedUserIdentity := &models.UserIdentity{}
	if err := os.Use(form.Code, storedUserIdentity); err != nil {
		zap.L().Error(
			"Unable to use token for application",
			zap.Object("AuthorizeLinkForm", form),
			zap.Error(err),
			zap.String(echo.HeaderXRequestID, helper.GetRequestIdFromHeader(ctx)),
		)

		return "", &models.CommonError{Code: `common`, Message: models.ErrorCannotUseToken}
	}

	user := &models.User{
		ID:            bson.NewObjectId(),
		AppID:         app.ID,
		Email:         storedUserIdentity.Email,
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
			zap.L().Error(
				"Unable to load password settings for application",
				zap.Object("AuthorizeLinkForm", form),
				zap.Error(err),
				zap.String(echo.HeaderXRequestID, helper.GetRequestIdFromHeader(ctx)),
			)

			return "", &models.CommonError{Code: `common`, Message: models.ErrorUnableValidatePassword}
		}
		if false == ps.IsValid(form.Password) {
			return "", &models.CommonError{Code: `password`, Message: models.ErrorPasswordIncorrect}
		}

		ipc, err := m.identityProviderService.FindByTypeAndName(app, models.AppIdentityProviderTypePassword, models.AppIdentityProviderNameDefault)
		if err != nil {
			zap.L().Warn(
				"Unable to get identity provider",
				zap.Object("AuthorizeLinkForm", form),
				zap.Error(err),
				zap.String(echo.HeaderXRequestID, helper.GetRequestIdFromHeader(ctx)),
			)
		}

		userIdentity, err := m.userIdentityService.Get(app, ipc, user.Email)

		be := models.NewBcryptEncryptor(&models.CryptConfig{Cost: ps.BcryptCost})

		err = be.Compare(userIdentity.Credential, form.Password)
		if err != nil {
			zap.L().Warn(
				"Unable to crypt password for application",
				zap.Object("AuthorizeLinkForm", form),
				zap.Error(err),
				zap.String(echo.HeaderXRequestID, helper.GetRequestIdFromHeader(ctx)),
			)

			return "", &models.CommonError{Code: `password`, Message: models.ErrorPasswordIncorrect}
		}

		mfa, err := m.mfaService.GetUserProviders(user)
		if err != nil {
			zap.L().Error(
				"Unable to load MFA providers for user",
				zap.Object("User", user),
				zap.Object("Application", app),
				zap.Error(err),
				zap.String(echo.HeaderXRequestID, helper.GetRequestIdFromHeader(ctx)),
			)

			return "", &models.CommonError{Code: `common`, Message: models.ErrorUnknownError}
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
				zap.L().Error(
					"Unable to create one-time token for application",
					zap.Object("UserIdentity", userIdentity),
					zap.Error(err),
					zap.String(echo.HeaderXRequestID, helper.GetRequestIdFromHeader(ctx)),
				)

				return "", &models.CommonError{Code: `common`, Message: models.ErrorCannotCreateToken}
			}

			return "", &models.MFARequiredError{HttpCode: http.StatusForbidden, Message: ott.Token}
		}

		user, err = m.userService.Get(userIdentity.UserID)
		if err != nil {
			zap.L().Error(
				"Unable to get user",
				zap.Object("UserIdentity", userIdentity),
				zap.Error(err),
				zap.String(echo.HeaderXRequestID, helper.GetRequestIdFromHeader(ctx)),
			)

			return "", &models.CommonError{Code: `email`, Message: models.ErrorLoginIncorrect}
		}
	case "new":
		if err := m.userService.Create(user); err != nil {
			zap.L().Error(
				"Unable to create user with identity",
				zap.Object("StoredUserIdentity", storedUserIdentity),
				zap.Object("User", user),
				zap.Error(err),
				zap.String(echo.HeaderXRequestID, helper.GetRequestIdFromHeader(ctx)),
			)

			return "", &models.CommonError{Code: `common`, Message: models.ErrorCreateUser}
		}
	default:
		zap.L().Error(
			"Unknown action type for social link",
			zap.Object("AuthorizeLinkForm", form),
			zap.Error(err),
			zap.String(echo.HeaderXRequestID, helper.GetRequestIdFromHeader(ctx)),
		)

		return "", &models.CommonError{Code: `common`, Message: models.ErrorUnknownError}
	}

	storedUserIdentity.ID = bson.NewObjectId()
	storedUserIdentity.UserID = user.ID
	storedUserIdentity.ApplicationID = app.ID
	if err := m.userIdentityService.Create(storedUserIdentity); err != nil {
		zap.L().Error(
			"Unable to create user identity for application",
			zap.Object("UserIdentity", storedUserIdentity),
			zap.Error(err),
			zap.String(echo.HeaderXRequestID, helper.GetRequestIdFromHeader(ctx)),
		)

		return "", &models.CommonError{Code: `common`, Message: models.ErrorCreateUserIdentity}
	}

	if err := m.authLogService.Add(ctx, user, ""); err != nil {
		zap.L().Error(
			"Unable to log authorization for user",
			zap.Object("User", user),
			zap.Error(err),
			zap.String(echo.HeaderXRequestID, helper.GetRequestIdFromHeader(ctx)),
		)

		return "", &models.CommonError{Code: `common`, Message: models.ErrorAddAuthLog}
	}

	reqACL, _, err := m.hydra.AcceptLoginRequest(
		form.Challenge,
		swagger.AcceptLoginRequest{
			Subject:     user.ID.Hex(),
			Remember:    false,
			RememberFor: 0,
		},
	)
	if err != nil {
		zap.L().Error(
			"Unable to accept login challenge",
			zap.Object("Oauth2LoginSubmitForm", form),
			zap.Error(err),
			zap.String(echo.HeaderXRequestID, helper.GetRequestIdFromHeader(ctx)),
		)
		return "", &models.CommonError{Code: `common`, Message: models.ErrorPasswordIncorrect}
	}

	return reqACL.RedirectTo, nil
}

func (m *LoginManager) CreateAuthUrl(ctx echo.Context, form *models.LoginPageForm) (string, error) {
	scopes := []string{"openid"}
	if form.Scopes != "" {
		scopes = strings.Split(form.Scopes, " ")
	}

	if form.RedirectUri == "" {
		form.RedirectUri = fmt.Sprintf("%s://%s/oauth2/callback", ctx.Scheme(), ctx.Request().Host)
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
