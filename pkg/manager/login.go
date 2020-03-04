package manager

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/ProtocolONE/auth1.protocol.one/pkg/database"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/models"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/service"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/validator"
	"github.com/globalsign/mgo"
	"github.com/globalsign/mgo/bson"
	"github.com/labstack/echo/v4"
	"github.com/ory/hydra/sdk/go/hydra/client/admin"
	models2 "github.com/ory/hydra/sdk/go/hydra/models"
	"github.com/pkg/errors"
)

var (
	SocialAccountCanLink = "link"
	SocialAccountSuccess = "success"
	SocialAccountError   = "error"
)

// LoginManagerInterface describes of methods for the manager.
type LoginManagerInterface interface {

	// ForwardUrl returns url for forwarding user to id provider
	ForwardUrl(challenge, provider, domain string) (string, error)

	// Callback handles auth_code returned by id provider
	Callback(provider, code, state, domain string) (string, error)

	// Providers returns list of available id providers for authentication
	Providers(challenge string) ([]*models.AppIdentityProvider, error)

	// Profile returns user profile attached to token
	Profile(token string) (*models.UserIdentitySocial, error)

	// Link links user profile attached to token with actual user in db
	Link(token string, userID bson.ObjectId, app *models.Application) error
}

// LoginManager is the login manager.
type LoginManager struct {
	userService             service.UserServiceInterface
	userIdentityService     service.UserIdentityServiceInterface
	mfaService              service.MfaServiceInterface
	authLogService          service.AuthLogServiceInterface
	identityProviderService service.AppIdentityProviderServiceInterface
	r                       service.InternalRegistry
}

// NewLoginManager return new login manager.
func NewLoginManager(h database.MgoSession, r service.InternalRegistry) LoginManagerInterface {
	m := &LoginManager{
		r:                       r,
		userService:             service.NewUserService(h),
		userIdentityService:     service.NewUserIdentityService(h),
		mfaService:              service.NewMfaService(h),
		authLogService:          service.NewAuthLogService(h),
		identityProviderService: service.NewAppIdentityProviderService(),
	}

	return m
}

type State struct {
	Challenge string `json:"challenge`
}

type SocialToken struct {
	UserIdentityID string                     `json:"user_ident"`
	Profile        *models.UserIdentitySocial `json:"profile"`
	Provider       string                     `json:"provider"`
}

func (m *LoginManager) Profile(token string) (*models.UserIdentitySocial, error) {
	var t SocialToken
	if err := m.r.OneTimeTokenService().Get(token, &t); err != nil {
		return nil, errors.Wrap(err, "can't get token data")
	}

	return t.Profile, nil
}

func (m *LoginManager) Providers(challenge string) ([]*models.AppIdentityProvider, error) {
	req, err := m.r.HydraAdminApi().GetLoginRequest(&admin.GetLoginRequestParams{Challenge: challenge, Context: context.TODO()})
	if err != nil {
		return nil, errors.Wrap(err, "can't get challenge data")
	}

	app, err := m.r.ApplicationService().Get(bson.ObjectIdHex(req.Payload.Client.ClientID))
	if err != nil {
		return nil, errors.Wrap(err, "can't get app data")
	}

	ips := m.identityProviderService.FindByType(app, models.AppIdentityProviderTypeSocial)
	return ips, nil
}

func (m *LoginManager) Callback(provider, code, state, domain string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(state)
	if err != nil {
		return "", errors.Wrap(err, "unable to decode state param")
	}

	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		return "", errors.Wrap(err, "unable to unmarshal state")
	}

	req, err := m.r.HydraAdminApi().GetLoginRequest(&admin.GetLoginRequestParams{Challenge: s.Challenge, Context: context.TODO()})
	if err != nil {
		return "", errors.Wrap(err, "can't get challenge data")
	}

	app, err := m.r.ApplicationService().Get(bson.ObjectIdHex(req.Payload.Client.ClientID))
	if err != nil {
		return "", errors.Wrap(err, "can't get app data")
	}

	ip := m.identityProviderService.FindByTypeAndName(app, models.AppIdentityProviderTypeSocial, provider)
	if ip == nil {
		return "", errors.New("identity provider not found")
	}

	clientProfile, err := m.identityProviderService.GetSocialProfile(context.TODO(), domain, code, ip)
	if err != nil || clientProfile == nil || clientProfile.ID == "" {
		if err == nil {
			err = errors.New("unable to load identity profile data")
		}
		return "", err
	}

	userIdentity, err := m.userIdentityService.Get(app, ip, clientProfile.ID)
	if err != nil && err != mgo.ErrNotFound {
		return "", errors.Wrap(err, "can't get user data")
	}

	if userIdentity != nil && err != mgo.ErrNotFound {

		id := userIdentity.UserID.Hex()
		// TODO sucessfully login
		reqACL, err := m.r.HydraAdminApi().AcceptLoginRequest(&admin.AcceptLoginRequestParams{
			Context:   context.TODO(),
			Challenge: s.Challenge,
			Body:      &models2.HandledLoginRequest{Subject: &id, Remember: false, RememberFor: 0}, // TODO remember
		})
		if err != nil {
			return "", errors.Wrap(err, "unable to accept login challenge")
		}

		return reqACL.Payload.RedirectTo, nil
	}

	if clientProfile.Email != "" {
		ipPass := m.identityProviderService.FindByTypeAndName(app, models.AppIdentityProviderTypePassword, models.AppIdentityProviderNameDefault)
		if ipPass == nil {
			return "", errors.New("default identity provider not found")
		}

		userIdentity, err := m.userIdentityService.Get(app, ipPass, clientProfile.Email)
		if err != nil && err != mgo.ErrNotFound {
			return "", errors.Wrap(err, "unable to get user identity")
		}

		if userIdentity != nil && err != mgo.ErrNotFound {
			ott, err := m.r.OneTimeTokenService().Create(&SocialToken{
				UserIdentityID: userIdentity.ID.Hex(),
				Profile:        clientProfile,
				Provider:       provider,
			}, app.OneTimeTokenSettings)
			if err != nil {
				return "", errors.Wrap(err, "unable to create one time link token")
			}

			return fmt.Sprintf("%s/social-existing/%s?login_challenge=%s&token=%s", domain, provider, s.Challenge, ott.Token), nil
		}
	}

	ott, err := m.r.OneTimeTokenService().Create(&SocialToken{
		Profile:  clientProfile,
		Provider: provider,
	}, app.OneTimeTokenSettings)
	if err != nil {
		return "", errors.Wrap(err, "unable to create one time link token")
	}

	return fmt.Sprintf("%s/social-new/%s?login_challenge=%s&token=%s", domain, provider, s.Challenge, ott.Token), nil
}

func (m *LoginManager) ForwardUrl(challenge, provider, domain string) (string, error) {
	req, err := m.r.HydraAdminApi().GetLoginRequest(&admin.GetLoginRequestParams{Challenge: challenge, Context: context.TODO()})
	if err != nil {
		return "", errors.Wrap(err, "can't get challenge data")
	}

	app, err := m.r.ApplicationService().Get(bson.ObjectIdHex(req.Payload.Client.ClientID))
	if err != nil {
		return "", errors.Wrap(err, "can't get app data")
	}

	ip := m.identityProviderService.FindByTypeAndName(app, models.AppIdentityProviderTypeSocial, provider)
	if ip == nil {
		return "", errors.New("identity provider not found")
	}

	return m.identityProviderService.GetAuthUrl(domain, ip, &State{Challenge: challenge})
}

func (m *LoginManager) Authorize(ctx echo.Context, form *models.AuthorizeForm) (string, *models.GeneralError) {
	app, err := m.r.ApplicationService().Get(bson.ObjectIdHex(form.ClientID))
	if err != nil {
		return "", &models.GeneralError{Code: "client_id", Message: models.ErrorClientIdIncorrect, Err: errors.Wrap(err, "Unable to load application")}
	}

	ip := m.identityProviderService.FindByTypeAndName(app, models.AppIdentityProviderTypeSocial, form.Connection)
	if ip == nil {
		return "", &models.GeneralError{Code: "client_id", Message: models.ErrorClientIdIncorrect, Err: errors.New("Unable to load identity provider")}
	}

	domain := fmt.Sprintf("%s://%s", ctx.Scheme(), ctx.Request().Host)
	u, err := m.identityProviderService.GetAuthUrl(domain, ip, form)
	if err != nil {
		return "", &models.GeneralError{Code: "common", Message: models.ErrorUnknownError, Err: errors.Wrap(err, "Unable to get auth url for identity provider")}
	}

	return u, nil
}

func (m *LoginManager) AuthorizeResult(ctx echo.Context, form *models.AuthorizeResultForm) (token *models.AuthorizeResultResponse, error *models.GeneralError) {
	authForm := &models.AuthorizeForm{}

	s, err := base64.StdEncoding.DecodeString(form.State)
	if err != nil {
		return nil, &models.GeneralError{Code: "common", Message: models.ErrorUnknownError, Err: errors.Wrap(err, "Unable to decode state param")}
	}

	if err := json.Unmarshal([]byte(s), authForm); err != nil {
		return nil, &models.GeneralError{Code: "common", Message: models.ErrorUnknownError, Err: errors.Wrap(err, "Unable to unmarshal auth form")}
	}

	app, err := m.r.ApplicationService().Get(bson.ObjectIdHex(authForm.ClientID))
	if err != nil {
		return nil, &models.GeneralError{Code: "client_id", Message: models.ErrorClientIdIncorrect, Err: errors.Wrap(err, "Unable to load application")}
	}

	ip := m.identityProviderService.FindByTypeAndName(app, models.AppIdentityProviderTypeSocial, authForm.Connection)
	if ip == nil {
		return nil, &models.GeneralError{Code: "common", Message: models.ErrorConnectionIncorrect, Err: errors.New("Unable to load identity provider")}
	}

	domain := fmt.Sprintf("%s://%s", ctx.Scheme(), ctx.Request().Host)
	cp, err := m.identityProviderService.GetSocialProfile(ctx.Request().Context(), domain, ctx.QueryParam("code"), ip)
	if err != nil || cp == nil || cp.ID == "" {
		if err == nil {
			err = errors.New("Unable to load identity profile data")
		}
		return nil, &models.GeneralError{Code: "common", Message: models.ErrorGetSocialData, Err: errors.WithStack(err)}
	}

	userIdentity, err := m.userIdentityService.Get(app, ip, cp.ID)
	if userIdentity != nil && err != mgo.ErrNotFound {
		user, err := m.userService.Get(userIdentity.UserID)
		if err != nil {
			return nil, &models.GeneralError{Code: "common", Message: models.ErrorLoginIncorrect, Err: errors.Wrap(err, "Unable to get user identity by email")}
		}

		if err := m.authLogService.Add(ctx.RealIP(), ctx.Request().UserAgent(), user); err != nil {
			return nil, &models.GeneralError{Code: "common", Message: models.ErrorAddAuthLog, Err: errors.Wrap(err, "Unable to add log authorization for user")}
		}

		ott, err := m.r.OneTimeTokenService().Create(userIdentity, app.OneTimeTokenSettings)
		if err != nil {
			return nil, &models.GeneralError{Code: "common", Message: models.ErrorCannotCreateToken, Err: errors.Wrap(err, "Unable to create OneTimeToken")}
		}

		return &models.AuthorizeResultResponse{
			Result:  SocialAccountSuccess,
			Payload: map[string]interface{}{"token": ott.Token},
		}, nil
	}

	if cp.Email != "" {
		ipPass := m.identityProviderService.FindByTypeAndName(app, models.AppIdentityProviderTypePassword, models.AppIdentityProviderNameDefault)
		if ipPass == nil {
			return nil, &models.GeneralError{Code: "common", Message: models.ErrorConnectionIncorrect, Err: errors.New("Unable to load identity provider")}
		}

		userIdentity, err := m.userIdentityService.Get(app, ipPass, cp.Email)
		if err != nil && err != mgo.ErrNotFound {
			return nil, &models.GeneralError{Code: "common", Message: models.ErrorUnknownError, Err: errors.Wrap(err, "Unable to get user identity")}
		}

		if userIdentity != nil {
			ss, err := m.r.ApplicationService().LoadSocialSettings()
			if err != nil {
				return nil, &models.GeneralError{Code: "common", Message: models.ErrorGetSocialSettings, Err: errors.Wrap(err, "Unable to load social settings")}
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
				return nil, &models.GeneralError{Code: "common", Message: models.ErrorCannotCreateToken, Err: errors.Wrap(err, "Unable to create OneTimeToken")}
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
		return nil, &models.GeneralError{Code: "common", Message: models.ErrorCreateUser, Err: errors.Wrap(err, "Unable to create user")}
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
		return nil, &models.GeneralError{Code: "common", Message: models.ErrorCreateUserIdentity, Err: errors.Wrap(err, "Unable to create user identity")}
	}

	if err := m.authLogService.Add(ctx.RealIP(), ctx.Request().UserAgent(), user); err != nil {
		return nil, &models.GeneralError{Code: "common", Message: models.ErrorAddAuthLog, Err: errors.Wrap(err, "Unable to add log authorization for user")}
	}

	ott, err := m.r.OneTimeTokenService().Create(&userIdentity, app.OneTimeTokenSettings)
	if err != nil {
		return nil, &models.GeneralError{Code: "common", Message: models.ErrorCannotCreateToken, Err: errors.Wrap(err, "Unable to create OneTimeToken")}
	}

	return &models.AuthorizeResultResponse{
		Result:  SocialAccountSuccess,
		Payload: map[string]interface{}{"token": ott.Token},
	}, nil
}

// Link links user profile attached to token with actual user in db
func (m *LoginManager) Link(token string, userID bson.ObjectId, app *models.Application) error {
	var t SocialToken
	if err := m.r.OneTimeTokenService().Use(token, &t); err != nil {
		return errors.Wrap(err, "can't get token data")
	}

	ip := m.identityProviderService.FindByTypeAndName(app, models.AppIdentityProviderTypeSocial, t.Provider)
	if ip == nil {
		return errors.New("identity provider not found")
	}

	userIdentity := &models.UserIdentity{
		ID:                 bson.NewObjectId(),
		UserID:             userID,
		ApplicationID:      app.ID,
		IdentityProviderID: ip.ID,
		Email:              t.Profile.Email,
		ExternalID:         t.Profile.ID,
		Name:               t.Profile.Name,
		CreatedAt:          time.Now(),
		UpdatedAt:          time.Now(),
		Credential:         t.Profile.Token,
	}

	return m.userIdentityService.Create(userIdentity)
}

func (m *LoginManager) AuthorizeLink(ctx echo.Context, form *models.AuthorizeLinkForm) (string, *models.GeneralError) {
	app, err := m.r.ApplicationService().Get(bson.ObjectIdHex(form.ClientID))
	if err != nil {
		return "", &models.GeneralError{Code: "client_id", Message: models.ErrorClientIdIncorrect, Err: errors.Wrap(err, "Unable to load application")}
	}

	storedUserIdentity := &models.UserIdentity{}
	if err := m.r.OneTimeTokenService().Use(form.Code, storedUserIdentity); err != nil {
		return "", &models.GeneralError{Code: "common", Message: models.ErrorCannotUseToken, Err: errors.Wrap(err, "Unable to use OneTimeToken")}
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
			return "", &models.GeneralError{Code: "password", Message: models.ErrorPasswordIncorrect, Err: errors.New(models.ErrorPasswordIncorrect)}
		}

		ipc := m.identityProviderService.FindByTypeAndName(app, models.AppIdentityProviderTypePassword, models.AppIdentityProviderNameDefault)
		if ipc == nil {
			return "", &models.GeneralError{Code: "client_id", Message: models.ErrorClientIdIncorrect, Err: errors.New("Unable to load identity provider")}
		}

		userIdentity, err := m.userIdentityService.Get(app, ipc, user.Email)
		if err != nil && err != mgo.ErrNotFound {
			return "", &models.GeneralError{Code: "client_id", Message: models.ErrorClientIdIncorrect, Err: errors.Wrap(err, "Unable to load user identity")}
		}

		be := models.NewBcryptEncryptor(&models.CryptConfig{Cost: app.PasswordSettings.BcryptCost})
		err = be.Compare(userIdentity.Credential, form.Password)
		if err != nil {
			return "", &models.GeneralError{Code: "password", Message: models.ErrorPasswordIncorrect, Err: errors.Wrap(err, "Unable to crypt password for application")}
		}

		mfa, err := m.mfaService.GetUserProviders(user)
		if err != nil {
			return "", &models.GeneralError{Code: "common", Message: models.ErrorUnknownError, Err: errors.Wrap(err, "Unable to load MFA providers")}
		}

		if len(mfa) > 0 {
			ott, err := m.r.OneTimeTokenService().Create(
				&models.UserMfaToken{
					UserIdentity: userIdentity,
					MfaProvider:  mfa[0],
				},
				app.OneTimeTokenSettings,
			)
			if err != nil {
				return "", &models.GeneralError{Code: "common", Message: models.ErrorCannotCreateToken, Err: errors.Wrap(err, "Unable to create OneTimeToken")}
			}

			return "", &models.GeneralError{HttpCode: http.StatusForbidden, Code: "common", Message: ott.Token}
		}

		user, err = m.userService.Get(userIdentity.UserID)
		if err != nil {
			return "", &models.GeneralError{Code: "email", Message: models.ErrorLoginIncorrect, Err: errors.Wrap(err, "Unable to get user")}
		}
	case "new":
		if err := m.userService.Create(user); err != nil {
			return "", &models.GeneralError{Code: "common", Message: models.ErrorCreateUser, Err: errors.Wrap(err, "Unable to create user")}
		}
	default:
		return "", &models.GeneralError{Code: "common", Message: models.ErrorUnknownError, Err: errors.New("Unknown action type for social link")}
	}

	storedUserIdentity.ID = bson.NewObjectId()
	storedUserIdentity.UserID = user.ID
	storedUserIdentity.ApplicationID = app.ID
	if err := m.userIdentityService.Create(storedUserIdentity); err != nil {
		return "", &models.GeneralError{Code: "common", Message: models.ErrorCreateUserIdentity, Err: errors.Wrap(err, "Unable to create user identity")}
	}

	if err := m.authLogService.Add(ctx.RealIP(), ctx.Request().UserAgent(), user); err != nil {
		return "", &models.GeneralError{Code: "common", Message: models.ErrorAddAuthLog, Err: errors.Wrap(err, "Unable to add log authorization for user")}
	}

	userId := user.ID.Hex()
	reqACL, err := m.r.HydraAdminApi().AcceptLoginRequest(&admin.AcceptLoginRequestParams{
		Challenge: form.Challenge,
		Body:      &models2.HandledLoginRequest{Subject: &userId, Remember: true, RememberFor: 0},
		Context:   ctx.Request().Context(),
	})
	if err != nil {
		return "", &models.GeneralError{Code: "common", Message: models.ErrorUnknownError, Err: errors.Wrap(err, "Unable to accept login challenge")}
	}

	return reqACL.Payload.RedirectTo, nil
}
