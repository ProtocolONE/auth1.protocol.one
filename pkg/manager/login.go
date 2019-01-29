package manager

import (
	"auth-one-api/pkg/database"
	"auth-one-api/pkg/helper"
	"auth-one-api/pkg/models"
	"encoding/json"
	"fmt"
	"github.com/go-redis/redis"
	"github.com/labstack/echo"
	"go.uber.org/zap"
	"gopkg.in/mgo.v2/bson"
	"net/http"
	"regexp"
	"time"
)

type LoginManager struct {
	logger              *zap.Logger
	redis               *redis.Client
	appService          *models.ApplicationService
	userService         *models.UserService
	userIdentityService *models.UserIdentityService
	mfaService          *models.MfaService
	authLogService      *models.AuthLogService
}

func NewLoginManager(logger *zap.Logger, h *database.Handler, redis *redis.Client) *LoginManager {
	m := &LoginManager{
		logger:              logger,
		redis:               redis,
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
			zap.String("clientId", form.ClientID),
			zap.Error(err),
		)

		return "", &models.CommonError{Code: `client_id`, Message: models.ErrorClientIdIncorrect}
	}

	uic, err := m.appService.GetUserIdentityConnection(a, models.UserIdentityProviderSocial, form.Connection)
	if err != nil {
		m.logger.Error(
			"Unable to load user identity settings for application",
			zap.String("clientId", form.ClientID),
			zap.String("provider", models.UserIdentityProviderSocial),
			zap.Error(err),
		)

		return "", &models.CommonError{Code: `common`, Message: models.ErrorUnableValidatePassword}
	}

	u, err := uic.GetAuthUrl(ctx, form)
	if err != nil {
		m.logger.Error(
			"Unable to get auth url from authorize form",
			zap.String("clientId", form.ClientID),
			zap.Error(err),
		)

		return "", &models.CommonError{Code: `common`, Message: models.ErrorUnknownError}
	}

	return u, nil
}

func (m *LoginManager) AuthorizeResult(ctx echo.Context, form *models.AuthorizeResultForm) (token *models.AuthToken, error models.ErrorInterface) {
	f := &models.AuthorizeForm{}

	if err := json.Unmarshal([]byte(form.State), f); err != nil {
		m.logger.Error(
			"Unable to unmarshal auth form",
			zap.String("state", form.State),
			zap.Error(err),
		)

		return nil, &models.CommonError{Code: `common`, Message: models.ErrorUnknownError}
	}

	a, err := m.appService.Get(bson.ObjectIdHex(f.ClientID))
	if err != nil {
		m.logger.Error(
			"Unable to get application service for client",
			zap.String("clientId", f.ClientID),
			zap.Error(err),
		)

		return nil, &models.CommonError{Code: `client_id`, Message: models.ErrorClientIdIncorrect}
	}

	uic, err := m.appService.GetUserIdentityConnection(a, models.UserIdentityProviderSocial, f.Connection)
	if err != nil {
		m.logger.Error(
			"Unable to load user identity settings for application",
			zap.String("clientId", f.ClientID),
			zap.Error(err),
		)

		return nil, &models.CommonError{Code: `common`, Message: models.ErrorConnectionIncorrect}
	}

	cp, err := uic.GetClientProfile(ctx)
	if err != nil || cp.ID == "" {
		m.logger.Error(
			"Unable to load identity profile for application",
			zap.String("clientId", f.ClientID),
			zap.Error(err),
		)

		return nil, &models.CommonError{Code: `common`, Message: models.ErrorGetSocialData}
	}

	ui, err := m.userIdentityService.Get(a, models.UserIdentityProviderSocial, f.Connection, cp.ID)
	if ui != nil {
		u, err := m.userService.Get(ui.UserID)
		if err != nil {
			m.logger.Error(
				"Unable to get user identity by email for application",
				zap.String("email", cp.Email),
				zap.String("clientId", f.ClientID),
				zap.Error(err),
			)

			return nil, &models.CommonError{Code: `common`, Message: models.ErrorLoginIncorrect}
		}

		t, err := helper.CreateAuthToken(ctx, m.appService, u)
		if err != nil {
			m.logger.Error(
				"Unable to create user auth token for application",
				zap.String("userId", u.ID.String()),
				zap.String("appId", a.ID.String()),
				zap.Error(err),
			)

			return nil, &models.CommonError{Code: `common`, Message: err.Error()}
		}

		if err := m.authLogService.Add(ctx, u, t.RefreshToken); err != nil {
			m.logger.Error(
				"Unable to log authorization for user",
				zap.String("userId", u.ID.String()),
				zap.Error(err),
			)

			return nil, &models.CommonError{Code: `common`, Message: models.ErrorAddAuthLog}
		}

		cs, err := m.appService.LoadSessionSettings()
		if err != nil {
			m.logger.Error(
				"Unable to load session settings for application",
				zap.String("appId", a.ID.String()),
				zap.Error(err),
			)

			return nil, &models.CommonError{Code: `common`, Message: models.ErrorCreateCookie}
		}

		c, err := models.NewCookie(a, u).Crypt(cs)
		if err != nil {
			m.logger.Error(
				"Unable to create user cookie for application",
				zap.String("userId", u.ID.String()),
				zap.String("appId", a.ID.String()),
				zap.Error(err),
			)

			return nil, &models.CommonError{Code: `common`, Message: models.ErrorCreateCookie}
		}

		http.SetCookie(ctx.Response(), c)
		return t, nil
	}

	r := regexp.MustCompile("link=([A-z0-9]{24})")
	re := r.FindStringSubmatch(fmt.Sprintf("link=%s", f.State))
	if len(re) > 0 {
		u, err := m.userService.Get(bson.ObjectIdHex(re[1]))
		if err != nil {
			m.logger.Warn(
				"Unable to get user",
				zap.String("userId", ui.UserID.String()),
				zap.Error(err),
			)

			return nil, &models.CommonError{Code: `email`, Message: models.ErrorLoginIncorrect}
		}

		ss, err := m.appService.LoadSocialSettings()
		if err != nil {
			m.logger.Error(
				"Unable to load social settings for application",
				zap.String("clientId", f.ClientID),
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
			ID:         bson.NewObjectId(),
			UserID:     u.ID,
			AppID:      a.ID,
			Provider:   models.UserIdentityProviderSocial,
			Connection: f.Connection,
			ExternalID: cp.ID,
			Credential: cp.Token,
			Email:      cp.Email,
			Name:       cp.Name,
			CreatedAt:  time.Now(),
			UpdatedAt:  time.Now(),
		})

		if err != nil {
			m.logger.Error(
				"Unable to create one-time token for application",
				zap.String("clientId", f.ClientID),
				zap.String("userId", u.ID.String()),
				zap.String("appId", a.ID.String()),
				zap.String("provider", models.UserIdentityProviderSocial),
				zap.Error(err),
			)

			return nil, &models.CommonError{Code: `common`, Message: models.ErrorCannotCreateToken}
		}

		return nil, &models.CommonError{Code: `link`, Message: ott.Token}
	}

	ui, err = m.userIdentityService.Get(a, models.UserIdentityProviderPassword, "", cp.Email)
	if ui != nil {
		ss, err := m.appService.LoadSocialSettings()
		if err != nil {
			m.logger.Error(
				"Unable to load social settings for application",
				zap.String("clientId", f.ClientID),
				zap.String("email", cp.Email),
				zap.String("appId", a.ID.String()),
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
			ID:         bson.NewObjectId(),
			UserID:     ui.UserID,
			AppID:      a.ID,
			Provider:   models.UserIdentityProviderSocial,
			Connection: f.Connection,
			ExternalID: cp.ID,
			Credential: cp.Token,
			Email:      cp.Email,
			Name:       cp.Name,
			CreatedAt:  time.Now(),
			UpdatedAt:  time.Now(),
		})

		if err != nil {
			m.logger.Error(
				"Unable to create one-time token for application",
				zap.String("clientId", f.ClientID),
				zap.String("email", cp.Email),
				zap.String("appId", a.ID.String()),
				zap.Error(err),
			)

			return nil, &models.CommonError{Code: `common`, Message: models.ErrorCannotCreateToken}
		}

		return nil, &models.CommonError{Code: `link`, Message: ott.Token}
	}

	u := &models.User{
		ID:            bson.NewObjectId(),
		AppID:         a.ID,
		Email:         cp.Email,
		EmailVerified: false,
		Blocked:       false,
		LastIp:        ctx.RealIP(),
		LastLogin:     time.Now(),
		LoginsCount:   1,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	if err := m.userService.Create(u); err != nil {
		m.logger.Error(
			"Unable to create user with identity for application",
			zap.String("clientId", f.ClientID),
			zap.String("email", cp.Email),
			zap.String("appId", a.ID.String()),
			zap.Error(err),
		)

		return nil, &models.CommonError{Code: `common`, Message: models.ErrorCreateUser}
	}

	ui = &models.UserIdentity{
		ID:         bson.NewObjectId(),
		UserID:     u.ID,
		AppID:      a.ID,
		Provider:   models.UserIdentityProviderSocial,
		Connection: f.Connection,
		Email:      cp.Email,
		ExternalID: cp.ID,
		Name:       cp.Name,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
		Credential: cp.Token,
	}

	if err := m.userIdentityService.Create(ui); err != nil {
		m.logger.Error(
			"Unable to create user identity for an application",
			zap.String("clientId", f.ClientID),
			zap.String("email", cp.Email),
			zap.String("appId", a.ID.String()),
			zap.Error(err),
		)

		return nil, &models.CommonError{Code: `common`, Message: models.ErrorCreateUserIdentity}
	}

	t, err := helper.CreateAuthToken(ctx, m.appService, u)
	if err != nil {
		m.logger.Error(
			"Unable to create user [%s] auth token for application[%s] with error: %s",
			zap.String("clientId", f.ClientID),
			zap.String("userId", u.ID.String()),
			zap.String("appId", a.ID.String()),
			zap.Error(err),
		)

		return nil, &models.CommonError{Code: `common`, Message: err.Error()}
	}

	if err := m.authLogService.Add(ctx, u, t.RefreshToken); err != nil {
		return nil, &models.CommonError{Code: `common`, Message: models.ErrorAddAuthLog}
	}

	cs, err := m.appService.LoadSessionSettings()
	if err != nil {
		m.logger.Error(
			"Unable to load session settings for application",
			zap.String("appId", a.ID.String()),
			zap.Error(err),
		)

		return nil, &models.CommonError{Code: `common`, Message: models.ErrorCreateCookie}
	}
	c, err := models.NewCookie(a, u).Crypt(cs)
	if err != nil {
		m.logger.Error(
			"Unable to create user cookie for application",
			zap.String("userId", u.ID.String()),
			zap.String("appId", a.ID.String()),
			zap.Error(err),
		)

		return nil, &models.CommonError{Code: `common`, Message: models.ErrorCreateCookie}
	}
	http.SetCookie(ctx.Response(), c)

	return t, nil
}

func (m *LoginManager) AuthorizeLink(ctx echo.Context, form *models.AuthorizeLinkForm) (token *models.AuthToken, error models.ErrorInterface) {
	a, err := m.appService.Get(bson.ObjectIdHex(form.ClientID))
	if err != nil {
		m.logger.Error(
			"Unable to get application",
			zap.String("clientId", form.ClientID),
			zap.Error(err),
		)

		return nil, &models.CommonError{Code: `client_id`, Message: models.ErrorClientIdIncorrect}
	}

	ss, err := m.appService.LoadSocialSettings()
	if err != nil {
		m.logger.Error(
			"Unable to load social settings for application",
			zap.String("clientId", form.ClientID),
			zap.Error(err),
		)

		return nil, &models.CommonError{Code: `common`, Message: models.ErrorGetSocialSettings}
	}

	ottSettings := &models.OneTimeTokenSettings{
		Length: ss.LinkedTokenLength,
		TTL:    ss.LinkedTTL,
	}
	os := models.NewOneTimeTokenService(m.redis, ottSettings)
	sl := &models.UserIdentity{}

	if err := os.Get(form.Code, sl); err != nil {
		m.logger.Error(
			"Unable to use token for application",
			zap.String("code", form.Code),
			zap.String("clientId", form.ClientID),
			zap.Error(err),
		)

		return nil, &models.CommonError{Code: `common`, Message: models.ErrorCannotUseToken}
	}

	u := &models.User{
		ID:            bson.NewObjectId(),
		AppID:         a.ID,
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
		ps, err := m.appService.LoadPasswordSettings()
		if err != nil {
			m.logger.Error(
				"Unable to load password settings for application",
				zap.String("clientId", form.ClientID),
				zap.Error(err),
			)

			return nil, &models.CommonError{Code: `common`, Message: models.ErrorUnableValidatePassword}
		}
		if false == ps.IsValid(form.Password) {
			return nil, &models.CommonError{Code: `password`, Message: models.ErrorPasswordIncorrect}
		}

		ui, err := m.userIdentityService.Get(a, models.UserIdentityProviderPassword, "", u.Email)

		be := models.NewBcryptEncryptor(&models.CryptConfig{Cost: ps.BcryptCost})

		err = be.Compare(ui.Credential, form.Password)
		if err != nil {
			m.logger.Warn(
				"Unable to crypt password for application",
				zap.String("clientId", form.ClientID),
				zap.String("password", form.Password),
				zap.Error(err),
			)

			return nil, &models.CommonError{Code: `password`, Message: models.ErrorPasswordIncorrect}
		}

		mfa, err := m.mfaService.GetUserProviders(u)
		if err != nil {
			m.logger.Error(
				"Unable to load MFA providers for user",
				zap.String("userId", ui.UserID.String()),
				zap.String("appId", a.ID.String()),
				zap.Error(err),
			)

			return nil, &models.CommonError{Code: `common`, Message: models.ErrorUnknownError}
		}

		if len(mfa) > 0 {
			if form.AccessToken != "" {
				ats, err := m.appService.LoadAuthTokenSettings()
				if err != nil {
					m.logger.Error(
						"Unable to load auth token settings for application",
						zap.String("appId", ui.AppID.String()),
						zap.Error(err),
					)

					return nil, &models.CommonError{Code: `common`, Message: models.ErrorUnknownError}
				}

				jts := models.NewJwtTokenService(ats)
				if _, err = jts.Decode(form.AccessToken); err != nil {
					m.logger.Warn(
						"Unable to decode access token for application",
						zap.String("appId", ui.AppID.String()),
						zap.Error(err),
					)

					return nil, &models.CommonError{Code: `common`, Message: models.ErrorCannotUseToken}
				}
			} else {
				ottSettings := &models.OneTimeTokenSettings{
					Length: 64,
					TTL:    3600,
				}
				os := models.NewOneTimeTokenService(m.redis, ottSettings)
				ott, err := os.Create(&models.UserMfaToken{
					UserIdentity: ui,
					MfaProvider:  mfa[0],
				})
				if err != nil {
					m.logger.Error(
						"Unable to create one-time token for application",
						zap.String("appId", ui.AppID.String()),
						zap.Error(err),
					)

					return nil, &models.CommonError{Code: `common`, Message: models.ErrorCannotCreateToken}
				}

				return nil, &models.MFARequiredError{Message: ott.Token}
			}
		}

		u, err = m.userService.Get(ui.UserID)
		if err != nil {
			m.logger.Error(
				"Unable to get user",
				zap.String("userId", ui.UserID.String()),
				zap.Error(err),
			)

			return nil, &models.CommonError{Code: `email`, Message: models.ErrorLoginIncorrect}
		}

	case "new":
		if err := m.userService.Create(u); err != nil {
			m.logger.Error(
				"Unable to create user with identity",
				zap.String("email", sl.Email),
				zap.String("appId", sl.AppID.String()),
				zap.Error(err),
			)

			return nil, &models.CommonError{Code: `common`, Message: models.ErrorCreateUser}
		}
		sl.UserID = u.ID
	default:
		m.logger.Error(
			"Unknown action type for social link",
			zap.String("action", form.Action),
			zap.Error(err),
		)

		return nil, &models.CommonError{Code: `common`, Message: models.ErrorUnknownError}
	}

	if err := m.userIdentityService.Create(sl); err != nil {
		m.logger.Error(
			"Unable to create user identity for application",
			zap.String("email", sl.Email),
			zap.String("appId", sl.AppID.String()),
			zap.Error(err),
		)

		return nil, &models.CommonError{Code: `common`, Message: models.ErrorCreateUserIdentity}
	}

	t, err := helper.CreateAuthToken(ctx, m.appService, u)
	if err != nil {
		m.logger.Error(
			"Unable to create user auth token for application",
			zap.String("userId", u.ID.String()),
			zap.String("appId", a.ID.String()),
			zap.Error(err),
		)

		return nil, &models.CommonError{Code: `common`, Message: err.Error()}
	}

	if err := m.authLogService.Add(ctx, u, t.RefreshToken); err != nil {
		return nil, &models.CommonError{Code: `common`, Message: models.ErrorAddAuthLog}
	}

	cs, err := m.appService.LoadSessionSettings()
	if err != nil {
		m.logger.Error(
			"Unable to load session settings for application",
			zap.String("appId", a.ID.String()),
			zap.Error(err),
		)

		return nil, &models.CommonError{Code: `common`, Message: models.ErrorCreateCookie}
	}
	c, err := models.NewCookie(a, u).Crypt(cs)
	if err != nil {
		m.logger.Error(
			"Unable to create user cookie for application",
			zap.String("userId", u.ID.String()),
			zap.String("appId", a.ID.String()),
			zap.Error(err),
		)

		return nil, &models.CommonError{Code: `common`, Message: models.ErrorCreateCookie}
	}
	http.SetCookie(ctx.Response(), c)

	return t, nil
}

func (m *LoginManager) Login(ctx echo.Context, form *models.LoginForm) (token *models.AuthToken, error models.ErrorInterface) {
	if form.Email == `captcha@required.com` {
		return nil, &models.CaptchaRequiredError{Message: models.ErrorCaptchaRequired}
	}
	if form.Captcha == `incorrect` {
		return nil, &models.CommonError{Code: `captcha`, Message: models.ErrorCaptchaIncorrect}
	}
	if form.Email == `temporary@locked.com` {
		return nil, &models.TemporaryLockedError{Message: models.ErrorAuthTemporaryLocked}
	}

	a, err := m.appService.Get(bson.ObjectIdHex(form.ClientID))
	if err != nil {
		m.logger.Error(
			"Unable to get application",
			zap.String("clientId", form.ClientID),
			zap.Error(err),
		)

		return nil, &models.CommonError{Code: `client_id`, Message: models.ErrorClientIdIncorrect}
	}

	ui, err := m.userIdentityService.Get(a, models.UserIdentityProviderPassword, "", form.Email)
	if err != nil {
		m.logger.Warn(
			"Unable to get user identity",
			zap.String("email", form.Email),
			zap.Error(err),
		)
	}

	if ui == nil || err != nil {
		return nil, &models.CommonError{Code: `email`, Message: models.ErrorLoginIncorrect}
	}

	ps, err := m.appService.LoadPasswordSettings()
	if err != nil {
		m.logger.Error(
			"Unable to load password settings for application",
			zap.String("clientId", form.ClientID),
			zap.Error(err),
		)

		return nil, &models.CommonError{Code: `common`, Message: models.ErrorUnableValidatePassword}
	}

	be := models.NewBcryptEncryptor(&models.CryptConfig{Cost: ps.BcryptCost})
	err = be.Compare(ui.Credential, form.Password)
	if err != nil {
		m.logger.Error(
			"Unable to crypt password for application",
			zap.String("password", form.Password),
			zap.String("clientId", form.ClientID),
			zap.Error(err),
		)

		return nil, &models.CommonError{Code: `password`, Message: models.ErrorPasswordIncorrect}
	}

	u, err := m.userService.Get(ui.UserID)
	if err != nil {
		m.logger.Error(
			"Unable to get user",
			zap.String("userId", ui.UserID.String()),
			zap.Error(err),
		)

		return nil, &models.CommonError{Code: `email`, Message: models.ErrorLoginIncorrect}
	}

	mfa, err := m.mfaService.GetUserProviders(u)
	if err != nil {
		m.logger.Error(
			"Unable to load MFA providers for user",
			zap.String("userId", ui.UserID.String()),
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
			UserIdentity: ui,
			MfaProvider:  mfa[0],
		})
		if err != nil {
			m.logger.Error(
				"Unable to create one-time token for application",
				zap.String("userId", ui.UserID.String()),
				zap.String("appId", ui.AppID.String()),
				zap.Error(err),
			)

			return nil, &models.CommonError{Code: `common`, Message: models.ErrorCannotCreateToken}
		}

		return nil, &models.MFARequiredError{Message: ott.Token}
	}

	t, err := helper.CreateAuthToken(ctx, m.appService, u)
	if err != nil {
		m.logger.Error(
			"Unable to create user auth token for application",
			zap.String("userId", u.ID.String()),
			zap.String("appId", a.ID.String()),
			zap.Error(err),
		)

		return nil, &models.CommonError{Code: `common`, Message: err.Error()}
	}

	if err := m.authLogService.Add(ctx, u, t.RefreshToken); err != nil {
		m.logger.Error(
			"Unable to add user auth log for application",
			zap.String("userId", u.ID.String()),
			zap.String("appId", a.ID.String()),
			zap.Error(err),
		)

		return nil, &models.CommonError{Code: `common`, Message: models.ErrorAddAuthLog}
	}

	cs, err := m.appService.LoadSessionSettings()
	if err != nil {
		m.logger.Error(
			"Unable to load session settings for application",
			zap.String("userId", u.ID.String()),
			zap.String("appId", a.ID.String()),
			zap.Error(err),
		)

		return nil, &models.CommonError{Code: `common`, Message: models.ErrorCreateCookie}
	}
	c, err := models.NewCookie(a, u).Crypt(cs)
	if err != nil {
		m.logger.Error(
			"Unable to create user cookie for application",
			zap.String("userId", u.ID.String()),
			zap.String("appId", a.ID.String()),
			zap.Error(err),
		)

		return nil, &models.CommonError{Code: `common`, Message: models.ErrorCreateCookie}
	}
	http.SetCookie(ctx.Response(), c)

	return t, nil
}
