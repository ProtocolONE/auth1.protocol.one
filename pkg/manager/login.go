package manager

import (
	"auth-one-api/pkg/database"
	"auth-one-api/pkg/helper"
	"auth-one-api/pkg/models"
	"encoding/json"
	"fmt"
	"github.com/go-redis/redis"
	"github.com/labstack/echo"
	"github.com/sirupsen/logrus"
	"gopkg.in/mgo.v2/bson"
	"net/http"
	"regexp"
	"time"
)

type LoginManager Config

func (m *LoginManager) Authorize(ctx echo.Context, form *models.AuthorizeForm) (string, models.ErrorInterface) {
	if form.Connection == `incorrect` {
		return "", &models.CommonError{Message: models.ErrorConnectionIncorrect}
	}

	as := models.NewApplicationService(m.Database)
	a, err := as.Get(bson.ObjectIdHex(form.ClientID))
	if err != nil {
		m.Logger.Warning(fmt.Sprintf("Unable to get application [%s] with error: %s", form.ClientID, err.Error()))
		return "", &models.CommonError{Code: `client_id`, Message: models.ErrorClientIdIncorrect}
	}

	uic, err := as.GetUserIdentityConnection(a, models.UserIdentityProviderSocial, form.Connection)
	if err != nil {
		m.Logger.Warning(fmt.Sprintf("Unable to load user identity settings an application [%s] with error: %s", form.ClientID, err.Error()))
		return "", &models.CommonError{Code: `common`, Message: models.ErrorUnableValidatePassword}
	}

	u, err := uic.GetAuthUrl(ctx, form)
	if err != nil {
		m.Logger.Warning(fmt.Sprintf("Unable to convert authorize form an application [%s] with error: %s", form.ClientID, err.Error()))
		return "", &models.CommonError{Code: `common`, Message: models.ErrorUnknownError}
	}

	return u, nil
}

func (m *LoginManager) AuthorizeResult(ctx echo.Context, form *models.AuthorizeResultForm) (token *models.AuthToken, error models.ErrorInterface) {
	f := &models.AuthorizeForm{}
	if err := json.Unmarshal([]byte(form.State), f); err != nil {
		m.Logger.Warning(fmt.Sprintf("Unable to unmarshal auth form [%s] with error: %s", form.State, err.Error()))
		return nil, &models.CommonError{Code: `common`, Message: models.ErrorUnknownError}
	}

	as := models.NewApplicationService(m.Database)
	a, err := as.Get(bson.ObjectIdHex(f.ClientID))
	if err != nil {
		m.Logger.Warning(fmt.Sprintf("Unable to get application [%s] with error: %s", f.ClientID, err.Error()))
		return nil, &models.CommonError{Code: `client_id`, Message: models.ErrorClientIdIncorrect}
	}

	uic, err := as.GetUserIdentityConnection(a, models.UserIdentityProviderSocial, f.Connection)
	if err != nil {
		m.Logger.Warning(fmt.Sprintf("Unable to load user identity settings an application [%s] with error: %s", f.ClientID, err.Error()))
		return nil, &models.CommonError{Code: `common`, Message: models.ErrorConnectionIncorrect}
	}

	cp, err := uic.GetClientProfile(ctx)
	if err != nil || cp.ID == "" {
		m.Logger.Warning(fmt.Sprintf("Unable to load identity profile an application [%s] with error: %s", f.ClientID, err.Error()))
		return nil, &models.CommonError{Code: `common`, Message: models.ErrorGetSocialData}
	}

	us := models.NewUserService(m.Database)
	uis := models.NewUserIdentityService(m.Database)
	ui, err := uis.Get(a, models.UserIdentityProviderSocial, f.Connection, cp.ID)
	if ui != nil {
		u, err := us.Get(ui.UserID)
		if err != nil {
			m.Logger.Warning(fmt.Sprintf("Unable to get user with identity [%s] an application [%s] with error: %s", cp.Email, f.ClientID, err.Error()))
			return nil, &models.CommonError{Code: `common`, Message: models.ErrorLoginIncorrect}
		}

		t, err := helper.CreateAuthToken(ctx, as, u)
		if err != nil {
			m.Logger.Warning(fmt.Sprintf("Unable to create user [%s] auth token an application [%s] with error: %s", u.ID, a.ID, err.Error()))
			return nil, &models.CommonError{Code: `common`, Message: err.Error()}
		}

		als := models.NewAuthLogService(m.Database)
		if err := als.Add(ctx, u, t.RefreshToken); err != nil {
			return nil, &models.CommonError{Code: `common`, Message: models.ErrorAddAuthLog}
		}

		cs, err := as.LoadSessionSettings()
		if err != nil {
			m.Logger.Warning(fmt.Sprintf("Unable to load session settings an application [%s] with error: %s", a.ID, err.Error()))
			return nil, &models.CommonError{Code: `common`, Message: models.ErrorCreateCookie}
		}
		c, err := models.NewCookie(a, u).Crypt(cs)
		if err != nil {
			m.Logger.Warning(fmt.Sprintf("Unable to create user [%s] cookie an application [%s] with error: %s", u.ID, a.ID, err.Error()))
			return nil, &models.CommonError{Code: `common`, Message: models.ErrorCreateCookie}
		}
		http.SetCookie(ctx.Response(), c)
		return t, nil
	}

	r := regexp.MustCompile("link=([A-z0-9]{24})")
	re := r.FindStringSubmatch(fmt.Sprintf("link=%s", f.State))
	if len(re) > 0 {
		u, err := us.Get(bson.ObjectIdHex(re[1]))
		if err != nil {
			m.Logger.Warning(fmt.Sprintf("Unable to get user [%s] with error: %s", ui.UserID, err.Error()))
			return nil, &models.CommonError{Code: `email`, Message: models.ErrorLoginIncorrect}
		}

		ss, err := as.LoadSocialSettings()
		if err != nil {
			m.Logger.Warning(fmt.Sprintf("Unable to load social settings an application [%s] with error: %s", f.ClientID, err.Error()))
			return nil, &models.CommonError{Code: `common`, Message: models.ErrorGetSocialSettings}
		}

		ottSettings := &models.OneTimeTokenSettings{
			Length: ss.LinkedTokenLength,
			TTL:    ss.LinkedTTL,
		}
		os := models.NewOneTimeTokenService(m.Redis, ottSettings)
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
			m.Logger.Warning(fmt.Sprintf("Unable to create one-time token an application [%s] with error: %s", f.ClientID, err.Error()))
			return nil, &models.CommonError{Code: `common`, Message: models.ErrorCannotCreateToken}
		}

		return nil, &models.CommonError{Code: `link`, Message: ott.Token}
	}

	ui, err = uis.Get(a, models.UserIdentityProviderPassword, "", cp.Email)
	if ui != nil {
		ss, err := as.LoadSocialSettings()
		if err != nil {
			m.Logger.Warning(fmt.Sprintf("Unable to load social settings an application [%s] with error: %s", f.ClientID, err.Error()))
			return nil, &models.CommonError{Code: `common`, Message: models.ErrorGetSocialSettings}
		}

		ottSettings := &models.OneTimeTokenSettings{
			Length: ss.LinkedTokenLength,
			TTL:    ss.LinkedTTL,
		}
		os := models.NewOneTimeTokenService(m.Redis, ottSettings)
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
			m.Logger.Warning(fmt.Sprintf("Unable to create one-time token an application [%s] with error: %s", f.ClientID, err.Error()))
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
	if err := us.Create(u); err != nil {
		m.Logger.Warning(fmt.Sprintf("Unable to create user with identity [%s] an application [%s] with error: %s", cp.Email, f.ClientID, err.Error()))
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
	if err := uis.Create(ui); err != nil {
		m.Logger.Warning(fmt.Sprintf("Unable to create user identity [%s] an application [%s] with error: %s", cp.Email, f.ClientID, err.Error()))
		return nil, &models.CommonError{Code: `common`, Message: models.ErrorCreateUserIdentity}
	}

	t, err := helper.CreateAuthToken(ctx, as, u)
	if err != nil {
		m.Logger.Warning(fmt.Sprintf("Unable to create user [%s] auth token an application [%s] with error: %s", u.ID, a.ID, err.Error()))
		return nil, &models.CommonError{Code: `common`, Message: err.Error()}
	}

	als := models.NewAuthLogService(m.Database)
	if err := als.Add(ctx, u, t.RefreshToken); err != nil {
		return nil, &models.CommonError{Code: `common`, Message: models.ErrorAddAuthLog}
	}

	cs, err := as.LoadSessionSettings()
	if err != nil {
		m.Logger.Warning(fmt.Sprintf("Unable to load session settings an application [%s] with error: %s", a.ID, err.Error()))
		return nil, &models.CommonError{Code: `common`, Message: models.ErrorCreateCookie}
	}
	c, err := models.NewCookie(a, u).Crypt(cs)
	if err != nil {
		m.Logger.Warning(fmt.Sprintf("Unable to create user [%s] cookie an application [%s] with error: %s", u.ID, a.ID, err.Error()))
		return nil, &models.CommonError{Code: `common`, Message: models.ErrorCreateCookie}
	}
	http.SetCookie(ctx.Response(), c)

	return t, nil
}

func (m *LoginManager) AuthorizeLink(ctx echo.Context, form *models.AuthorizeLinkForm) (token *models.AuthToken, error models.ErrorInterface) {
	as := models.NewApplicationService(m.Database)
	a, err := as.Get(bson.ObjectIdHex(form.ClientID))
	if err != nil {
		m.Logger.Warning(fmt.Sprintf("Unable to get application [%s] with error: %s", form.ClientID, err.Error()))
		return nil, &models.CommonError{Code: `client_id`, Message: models.ErrorClientIdIncorrect}
	}

	ss, err := as.LoadSocialSettings()
	if err != nil {
		m.Logger.Warning(fmt.Sprintf("Unable to load social settings an application [%s] with error: %s", form.ClientID, err.Error()))
		return nil, &models.CommonError{Code: `common`, Message: models.ErrorGetSocialSettings}
	}

	ottSettings := &models.OneTimeTokenSettings{
		Length: ss.LinkedTokenLength,
		TTL:    ss.LinkedTTL,
	}
	os := models.NewOneTimeTokenService(m.Redis, ottSettings)
	sl := &models.UserIdentity{}
	if err := os.Get(form.Code, sl); err != nil {
		m.Logger.Warning(fmt.Sprintf("Unable to use token an application [%s] with error: %s", form.Code, err.Error()))
		return nil, &models.CommonError{Code: `common`, Message: models.ErrorCannotUseToken}
	}

	uis := models.NewUserIdentityService(m.Database)
	us := models.NewUserService(m.Database)
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
		ps, err := as.LoadPasswordSettings()
		if err != nil {
			m.Logger.Warning(fmt.Sprintf("Unable to load password settings an application [%s] with error: %s", form.ClientID, err.Error()))
			return nil, &models.CommonError{Code: `common`, Message: models.ErrorUnableValidatePassword}
		}
		if false == ps.IsValid(form.Password) {
			return nil, &models.CommonError{Code: `password`, Message: models.ErrorPasswordIncorrect}
		}

		ui, err := uis.Get(a, models.UserIdentityProviderPassword, "", sl.Email)

		be := models.NewBcryptEncryptor(&models.CryptConfig{Cost: ps.BcryptCost})
		err = be.Compare(ui.Credential, form.Password)
		if err != nil {
			m.Logger.Warning(fmt.Sprintf("Unable to crypt password [%s] an application [%s] with error: %s", form.Password, form.ClientID, err.Error()))
			return nil, &models.CommonError{Code: `password`, Message: models.ErrorPasswordIncorrect}
		}

		ms := models.NewMfaService(m.Database)
		mfa, err := ms.GetUserProviders(u)
		if err != nil {
			m.Logger.Warning(fmt.Sprintf("Unable to load MFA providers for user [%s] with error: %s", ui.UserID, err.Error()))
			return nil, &models.CommonError{Code: `common`, Message: models.ErrorUnknownError}
		} else if len(mfa) > 0 {
			if form.AccessToken != "" {
				ats, err := as.LoadAuthTokenSettings()
				if err != nil {
					m.Logger.Warning(fmt.Sprintf("Unable to load auth token settings an application [%s] with error: %s", ui.AppID, err.Error()))
					return nil, &models.CommonError{Code: `common`, Message: models.ErrorUnknownError}
				}

				jts := models.NewJwtTokenService(ats)
				if _, err = jts.Decode(form.AccessToken); err != nil {
					m.Logger.Warning(fmt.Sprintf("Unable to decode access token an application [%s] with error: %s", ui.AppID, err.Error()))
					return nil, &models.CommonError{Code: `common`, Message: models.ErrorCannotUseToken}
				}
			} else {
				ottSettings := &models.OneTimeTokenSettings{
					Length: 64,
					TTL:    3600,
				}
				os := models.NewOneTimeTokenService(m.Redis, ottSettings)
				ott, err := os.Create(&models.UserMfaToken{
					UserIdentity: ui,
					MfaProvider:  mfa[0],
				})
				if err != nil {
					m.Logger.Warning(fmt.Sprintf("Unable to create one-time token an application [%s] with error: %s", ui.AppID, err.Error()))
					return nil, &models.CommonError{Code: `common`, Message: models.ErrorCannotCreateToken}
				}

				return nil, &models.MFARequiredError{Message: ott.Token}
			}
		}

		u, err = us.Get(ui.UserID)
		if err != nil {
			m.Logger.Warning(fmt.Sprintf("Unable to get user [%s] with error: %s", ui.UserID, err.Error()))
			return nil, &models.CommonError{Code: `email`, Message: models.ErrorLoginIncorrect}
		}
	case "new":
		if err := us.Create(u); err != nil {
			m.Logger.Warning(fmt.Sprintf("Unable to create user with identity [%s] an application [%s] with error: %s", sl.Email, sl.AppID, err.Error()))
			return nil, &models.CommonError{Code: `common`, Message: models.ErrorCreateUser}
		}
		sl.UserID = u.ID
	default:
		m.Logger.Warning(fmt.Sprintf("Unknown action type for social link [%s] with error: %s", form.Action, err.Error()))
		return nil, &models.CommonError{Code: `common`, Message: models.ErrorUnknownError}
	}

	if err := uis.Create(sl); err != nil {
		m.Logger.Warning(fmt.Sprintf("Unable to create user identity [%s] an application [%s] with error: %s", sl.Email, sl.AppID, err.Error()))
		return nil, &models.CommonError{Code: `common`, Message: models.ErrorCreateUserIdentity}
	}

	t, err := helper.CreateAuthToken(ctx, as, u)
	if err != nil {
		m.Logger.Warning(fmt.Sprintf("Unable to create user [%s] auth token an application [%s] with error: %s", u.ID, a.ID, err.Error()))
		return nil, &models.CommonError{Code: `common`, Message: err.Error()}
	}

	als := models.NewAuthLogService(m.Database)
	if err := als.Add(ctx, u, t.RefreshToken); err != nil {
		return nil, &models.CommonError{Code: `common`, Message: models.ErrorAddAuthLog}
	}

	cs, err := as.LoadSessionSettings()
	if err != nil {
		m.Logger.Warning(fmt.Sprintf("Unable to load session settings an application [%s] with error: %s", a.ID, err.Error()))
		return nil, &models.CommonError{Code: `common`, Message: models.ErrorCreateCookie}
	}
	c, err := models.NewCookie(a, u).Crypt(cs)
	if err != nil {
		m.Logger.Warning(fmt.Sprintf("Unable to create user [%s] cookie an application [%s] with error: %s", u.ID, a.ID, err.Error()))
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

	as := models.NewApplicationService(m.Database)
	a, err := as.Get(bson.ObjectIdHex(form.ClientID))
	if err != nil {
		m.Logger.Warning(fmt.Sprintf("Unable to get application [%s] with error: %s", form.ClientID, err.Error()))
		return nil, &models.CommonError{Code: `client_id`, Message: models.ErrorClientIdIncorrect}
	}

	uis := models.NewUserIdentityService(m.Database)
	ui, err := uis.Get(a, models.UserIdentityProviderPassword, "", form.Email)
	if ui == nil || err != nil {
		if err != nil {
			m.Logger.Warning(fmt.Sprintf("Unable to get user identity [%s] with error: %s", form.Email, err.Error()))
		}
		return nil, &models.CommonError{Code: `email`, Message: models.ErrorLoginIncorrect}
	}

	ps, err := as.LoadPasswordSettings()
	if err != nil {
		m.Logger.Warning(fmt.Sprintf("Unable to load password settings an application [%s] with error: %s", form.ClientID, err.Error()))
		return nil, &models.CommonError{Code: `common`, Message: models.ErrorUnableValidatePassword}
	}

	be := models.NewBcryptEncryptor(&models.CryptConfig{Cost: ps.BcryptCost})
	err = be.Compare(ui.Credential, form.Password)
	if err != nil {
		m.Logger.Warning(fmt.Sprintf("Unable to crypt password [%s] an application [%s] with error: %s", form.Password, form.ClientID, err.Error()))
		return nil, &models.CommonError{Code: `password`, Message: models.ErrorPasswordIncorrect}
	}

	us := models.NewUserService(m.Database)
	u, err := us.Get(ui.UserID)
	if err != nil {
		m.Logger.Warning(fmt.Sprintf("Unable to get user [%s] with error: %s", ui.UserID, err.Error()))
		return nil, &models.CommonError{Code: `email`, Message: models.ErrorLoginIncorrect}
	}

	ms := models.NewMfaService(m.Database)
	mfa, err := ms.GetUserProviders(u)
	if err != nil {
		m.Logger.Warning(fmt.Sprintf("Unable to load MFA providers for user [%s] with error: %s", ui.UserID, err.Error()))
		return nil, &models.CommonError{Code: `common`, Message: models.ErrorUnknownError}
	} else if len(mfa) > 0 {
		ottSettings := &models.OneTimeTokenSettings{
			Length: 64,
			TTL:    3600,
		}
		os := models.NewOneTimeTokenService(m.Redis, ottSettings)
		ott, err := os.Create(&models.UserMfaToken{
			UserIdentity: ui,
			MfaProvider:  mfa[0],
		})
		if err != nil {
			m.Logger.Warning(fmt.Sprintf("Unable to create one-time token an application [%s] with error: %s", ui.AppID, err.Error()))
			return nil, &models.CommonError{Code: `common`, Message: models.ErrorCannotCreateToken}
		}

		return nil, &models.MFARequiredError{Message: ott.Token}
	}

	t, err := helper.CreateAuthToken(ctx, as, u)
	if err != nil {
		m.Logger.Warning(fmt.Sprintf("Unable to create user [%s] auth token an application [%s] with error: %s", u.ID, a.ID, err.Error()))
		return nil, &models.CommonError{Code: `common`, Message: err.Error()}
	}

	als := models.NewAuthLogService(m.Database)
	if err := als.Add(ctx, u, t.RefreshToken); err != nil {
		m.Logger.Warning(fmt.Sprintf("Unable to add user [%s] auth log an application [%s] with error: %s", u.ID, a.ID, err.Error()))
		return nil, &models.CommonError{Code: `common`, Message: models.ErrorAddAuthLog}
	}

	cs, err := as.LoadSessionSettings()
	if err != nil {
		m.Logger.Warning(fmt.Sprintf("Unable to load session settings an application [%s] with error: %s", a.ID, err.Error()))
		return nil, &models.CommonError{Code: `common`, Message: models.ErrorCreateCookie}
	}
	c, err := models.NewCookie(a, u).Crypt(cs)
	if err != nil {
		m.Logger.Warning(fmt.Sprintf("Unable to create user [%s] cookie an application [%s] with error: %s", u.ID, a.ID, err.Error()))
		return nil, &models.CommonError{Code: `common`, Message: models.ErrorCreateCookie}
	}
	http.SetCookie(ctx.Response(), c)

	return t, nil
}

func InitLoginManager(logger *logrus.Entry, h *database.Handler, redis *redis.Client) LoginManager {
	m := LoginManager{
		Database: h,
		Logger:   logger,
		Redis:    redis,
	}

	return m
}
