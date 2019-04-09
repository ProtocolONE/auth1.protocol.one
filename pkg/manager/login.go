package manager

import (
	"encoding/base64"
	"encoding/json"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/models"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/service"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/validator"
	"github.com/globalsign/mgo"
	"github.com/globalsign/mgo/bson"
	"github.com/go-redis/redis"
	"github.com/labstack/echo/v4"
	"github.com/ory/hydra/sdk/go/hydra/swagger"
	"go.uber.org/zap"
	"net/http"
	"time"
)

var (
	SocialAccountCanLink = "link"
	SocialAccountSuccess = "success"
	SocialAccountError   = "error"
)

type LoginManager struct {
	Logger                  *zap.Logger
	redis                   *redis.Client
	userService             *models.UserService
	userIdentityService     *models.UserIdentityService
	mfaService              *models.MfaService
	authLogService          *models.AuthLogService
	identityProviderService *service.AppIdentityProviderService
	r                       service.InternalRegistry
}

func NewLoginManager(h *mgo.Session, l *zap.Logger, redis *redis.Client, r service.InternalRegistry) *LoginManager {
	m := &LoginManager{
		Logger:                  l,
		redis:                   redis,
		r:                       r,
		userService:             models.NewUserService(h),
		userIdentityService:     models.NewUserIdentityService(h),
		mfaService:              models.NewMfaService(h),
		authLogService:          models.NewAuthLogService(h),
		identityProviderService: service.NewAppIdentityProviderService(),
	}

	return m
}

func (m *LoginManager) Authorize(ctx echo.Context, form *models.AuthorizeForm) (string, models.ErrorInterface) {
	if form.Connection == `incorrect` {
		return "", &models.CommonError{Message: models.ErrorConnectionIncorrect}
	}

	app, err := m.r.ApplicationService().Get(bson.ObjectIdHex(form.ClientID))
	if err != nil {
		m.Logger.Warn("Unable to load application", zap.Error(err))
		return "", &models.CommonError{Code: `client_id`, Message: models.ErrorClientIdIncorrect}
	}

	ip := m.identityProviderService.FindByTypeAndName(app, models.AppIdentityProviderTypeSocial, form.Connection)
	if ip != nil {
		m.Logger.Error(
			"Unable to load user identity settings for application",
			zap.Object("AuthorizeForm", form),
			zap.String("Provider", models.AppIdentityProviderTypeSocial),
		)

		return "", &models.CommonError{Code: `common`, Message: models.ErrorUnableValidatePassword}
	}

	u, err := m.identityProviderService.GetAuthUrl(ctx, ip, form)
	if err != nil {
		m.Logger.Error(
			"Unable to get auth url from authorize form",
			zap.Object("AuthorizeForm", form),
			zap.Error(err),
		)

		return "", &models.CommonError{Code: `common`, Message: models.ErrorUnknownError}
	}

	return u, nil
}

func (m *LoginManager) AuthorizeResult(ctx echo.Context, form *models.AuthorizeResultForm) (token *models.AuthorizeResultResponse, error models.ErrorInterface) {
	authForm := &models.AuthorizeForm{}

	s, err := base64.StdEncoding.DecodeString(form.State)
	if err != nil {
		m.Logger.Error(
			"Unable to decode state param",
			zap.Object("AuthorizeResultForm", form),
			zap.Error(err),
		)

		return nil, &models.CommonError{Code: `common`, Message: models.ErrorUnknownError}
	}

	if err := json.Unmarshal([]byte(s), authForm); err != nil {
		m.Logger.Error(
			"Unable to unmarshal auth form",
			zap.Object("AuthorizeResultForm", form),
			zap.Error(err),
		)

		return nil, &models.CommonError{Code: `common`, Message: models.ErrorUnknownError}
	}

	app, err := m.r.ApplicationService().Get(bson.ObjectIdHex(authForm.ClientID))
	if err != nil {
		m.Logger.Warn("Unable to load application", zap.Error(err))
		return nil, &models.CommonError{Code: `client_id`, Message: models.ErrorClientIdIncorrect}
	}

	ip := m.identityProviderService.FindByTypeAndName(app, models.AppIdentityProviderTypeSocial, authForm.Connection)
	if ip != nil {
		m.Logger.Error(
			"Unable to load user identity settings for application",
			zap.Object("AuthorizeForm", authForm),
		)

		return nil, &models.CommonError{Code: `common`, Message: models.ErrorConnectionIncorrect}
	}

	cp, err := m.identityProviderService.GetSocialProfile(ctx, ip)
	if err != nil || cp.ID == "" {
		m.Logger.Error(
			"Unable to load identity profile for application",
			zap.Object("AuthorizeForm", authForm),
		)

		return nil, &models.CommonError{Code: `common`, Message: models.ErrorGetSocialData}
	}

	userIdentity, err := m.userIdentityService.Get(app, ip, cp.ID)
	if userIdentity != nil && err != mgo.ErrNotFound {
		user, err := m.userService.Get(userIdentity.UserID)
		if err != nil {
			m.Logger.Error(
				"Unable to get user identity by email for application",
				zap.Object("UserIdentitySocial", cp),
				zap.Object("AuthorizeForm", authForm),
				zap.Error(err),
			)

			return nil, &models.CommonError{Code: `common`, Message: models.ErrorLoginIncorrect}
		}

		if err := m.authLogService.Add(ctx, user, ""); err != nil {
			m.Logger.Error(
				"Unable to log authorization for user",
				zap.Object("User", user),
				zap.Error(err),
			)

			return nil, &models.CommonError{Code: `common`, Message: models.ErrorAddAuthLog}
		}

		ottSettings := &models.OneTimeTokenSettings{
			Length: 64,
			TTL:    3600,
		}
		ott, err := m.r.OneTimeTokenService().Create(userIdentity, ottSettings)
		if err != nil {
			m.Logger.Error(
				"Unable to create one-time token for application",
				zap.Object("LoginForm", form),
				zap.Object("User", user),
				zap.Object("Application", app),
				zap.Error(err),
			)

			return nil, &models.CommonError{Code: `common`, Message: models.ErrorCannotCreateToken}
		}

		return &models.AuthorizeResultResponse{
			Result:  SocialAccountSuccess,
			Payload: map[string]interface{}{"token": ott.Token},
		}, nil
	}

	if cp.Email != "" {
		ipPass := m.identityProviderService.FindByTypeAndName(app, models.AppIdentityProviderTypePassword, models.AppIdentityProviderNameDefault)
		if ipPass != nil {
			m.Logger.Error(
				"Unable to load user identity settings for application",
				zap.Object("AuthorizeForm", authForm),
			)

			return nil, &models.CommonError{Code: `common`, Message: models.ErrorConnectionIncorrect}
		}

		userIdentity, err := m.userIdentityService.Get(app, ipPass, cp.Email)
		if err != nil && err != mgo.ErrNotFound {
			m.Logger.Warn(
				"Unable to get user identity",
				zap.Object("AuthorizeResultForm", form),
				zap.Error(err),
			)
		}

		if userIdentity != nil {
			ss, err := m.r.ApplicationService().LoadSocialSettings()
			if err != nil {
				m.Logger.Error(
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
			userIdentity.IdentityProviderID = ip.ID
			userIdentity.ExternalID = cp.ID
			userIdentity.Email = cp.Email
			ott, err := m.r.OneTimeTokenService().Create(userIdentity, ottSettings)

			if err != nil {
				m.Logger.Error(
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
		m.Logger.Error(
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
		IdentityProviderID: ip.ID,
		Email:              cp.Email,
		ExternalID:         cp.ID,
		Name:               cp.Name,
		CreatedAt:          time.Now(),
		UpdatedAt:          time.Now(),
		Credential:         cp.Token,
	}
	if err := m.userIdentityService.Create(userIdentity); err != nil {
		m.Logger.Error(
			"Unable to create user identity for an application",
			zap.Object("AuthorizeForm", authForm),
			zap.Object("UserIdentitySocial", cp),
			zap.Object("Application", app),
			zap.Error(err),
		)

		return nil, &models.CommonError{Code: `common`, Message: models.ErrorCreateUserIdentity}
	}

	if err := m.authLogService.Add(ctx, user, ""); err != nil {
		m.Logger.Error(
			"Unable to log auth for user",
			zap.Object("User", user),
		)

		return nil, &models.CommonError{Code: `common`, Message: models.ErrorAddAuthLog}
	}

	ottSettings := &models.OneTimeTokenSettings{
		Length: 64,
		TTL:    3600,
	}
	ott, err := m.r.OneTimeTokenService().Create(&userIdentity, ottSettings)
	if err != nil {
		m.Logger.Error(
			"Unable to create one-time token for application",
			zap.Object("LoginForm", form),
			zap.Object("User", user),
			zap.Object("Application", app),
			zap.Error(err),
		)

		return nil, &models.CommonError{Code: `common`, Message: models.ErrorCannotCreateToken}
	}

	return &models.AuthorizeResultResponse{
		Result:  SocialAccountSuccess,
		Payload: map[string]interface{}{"token": ott.Token},
	}, nil
}

func (m *LoginManager) AuthorizeLink(ctx echo.Context, form *models.AuthorizeLinkForm) (string, models.ErrorInterface) {
	app, err := m.r.ApplicationService().Get(bson.ObjectIdHex(form.ClientID))
	if err != nil {
		m.Logger.Warn("Unable to load application", zap.Error(err))
		return "", &models.CommonError{Code: `client_id`, Message: models.ErrorClientIdIncorrect}
	}

	storedUserIdentity := &models.UserIdentity{}
	if err := m.r.OneTimeTokenService().Use(form.Code, storedUserIdentity); err != nil {
		m.Logger.Error(
			"Unable to use token for application",
			zap.Object("AuthorizeLinkForm", form),
			zap.Error(err),
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
		if false == validator.IsPasswordValid(app, form.Password) {
			return "", &models.CommonError{Code: `password`, Message: models.ErrorPasswordIncorrect}
		}

		ipc := m.identityProviderService.FindByTypeAndName(app, models.AppIdentityProviderTypePassword, models.AppIdentityProviderNameDefault)
		if ipc != nil {
			m.Logger.Warn(
				"Unable to get identity provider",
				zap.Object("AuthorizeLinkForm", form),
			)
		}

		userIdentity, err := m.userIdentityService.Get(app, ipc, user.Email)

		be := models.NewBcryptEncryptor(&models.CryptConfig{Cost: app.PasswordSettings.BcryptCost})

		err = be.Compare(userIdentity.Credential, form.Password)
		if err != nil {
			m.Logger.Warn(
				"Unable to crypt password for application",
				zap.Object("AuthorizeLinkForm", form),
				zap.Error(err),
			)

			return "", &models.CommonError{Code: `password`, Message: models.ErrorPasswordIncorrect}
		}

		mfa, err := m.mfaService.GetUserProviders(user)
		if err != nil {
			m.Logger.Error(
				"Unable to load MFA providers for user",
				zap.Object("User", user),
				zap.Object("Application", app),
				zap.Error(err),
			)

			return "", &models.CommonError{Code: `common`, Message: models.ErrorUnknownError}
		}

		if len(mfa) > 0 {
			ottSettings := &models.OneTimeTokenSettings{
				Length: 64,
				TTL:    3600,
			}
			ott, err := m.r.OneTimeTokenService().Create(&models.UserMfaToken{
				UserIdentity: userIdentity,
				MfaProvider:  mfa[0],
			}, ottSettings)
			if err != nil {
				m.Logger.Error(
					"Unable to create one-time token for application",
					zap.Object("UserIdentity", userIdentity),
					zap.Error(err),
				)

				return "", &models.CommonError{Code: `common`, Message: models.ErrorCannotCreateToken}
			}

			return "", &models.MFARequiredError{HttpCode: http.StatusForbidden, Message: ott.Token}
		}

		user, err = m.userService.Get(userIdentity.UserID)
		if err != nil {
			m.Logger.Error(
				"Unable to get user",
				zap.Object("UserIdentity", userIdentity),
				zap.Error(err),
			)

			return "", &models.CommonError{Code: `email`, Message: models.ErrorLoginIncorrect}
		}
	case "new":
		if err := m.userService.Create(user); err != nil {
			m.Logger.Error(
				"Unable to create user with identity",
				zap.Object("StoredUserIdentity", storedUserIdentity),
				zap.Object("User", user),
				zap.Error(err),
			)

			return "", &models.CommonError{Code: `common`, Message: models.ErrorCreateUser}
		}
	default:
		m.Logger.Error(
			"Unknown action type for social link",
			zap.Object("AuthorizeLinkForm", form),
			zap.Error(err),
		)

		return "", &models.CommonError{Code: `common`, Message: models.ErrorUnknownError}
	}

	storedUserIdentity.ID = bson.NewObjectId()
	storedUserIdentity.UserID = user.ID
	storedUserIdentity.ApplicationID = app.ID
	if err := m.userIdentityService.Create(storedUserIdentity); err != nil {
		m.Logger.Error(
			"Unable to create user identity for application",
			zap.Object("UserIdentity", storedUserIdentity),
			zap.Error(err),
		)

		return "", &models.CommonError{Code: `common`, Message: models.ErrorCreateUserIdentity}
	}

	if err := m.authLogService.Add(ctx, user, ""); err != nil {
		m.Logger.Error(
			"Unable to log authorization for user",
			zap.Object("User", user),
			zap.Error(err),
		)

		return "", &models.CommonError{Code: `common`, Message: models.ErrorAddAuthLog}
	}

	reqACL, _, err := m.r.HydraSDK().AcceptLoginRequest(
		form.Challenge,
		swagger.AcceptLoginRequest{
			Subject:     user.ID.Hex(),
			Remember:    false,
			RememberFor: 0,
		},
	)
	if err != nil {
		m.Logger.Error(
			"Unable to accept login challenge",
			zap.Object("Oauth2LoginSubmitForm", form),
			zap.Error(err),
		)
		return "", &models.CommonError{Code: `common`, Message: models.ErrorPasswordIncorrect}
	}

	return reqACL.RedirectTo, nil
}
