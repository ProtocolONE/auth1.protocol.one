package manager

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
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
	"net/http"
	"time"
)

var (
	SocialAccountCanLink = "link"
	SocialAccountSuccess = "success"
	SocialAccountError   = "error"
)

type LoginManager struct {
	userService             service.UserServiceInterface
	userIdentityService     service.UserIdentityServiceInterface
	mfaService              service.MfaServiceInterface
	authLogService          service.AuthLogServiceInterface
	identityProviderService service.AppIdentityProviderServiceInterface
	r                       service.InternalRegistry
}

func NewLoginManager(h database.Session, r service.InternalRegistry) *LoginManager {
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

func (m *LoginManager) Authorize(ctx echo.Context, form *models.AuthorizeForm) (string, *models.GeneralError) {
	if form.Connection == `incorrect` {
		return "", &models.GeneralError{Message: models.ErrorConnectionIncorrect, Err: errors.New("Invalid connection name")}
	}

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
	if err != nil || cp.ID == "" {
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

		if err := m.authLogService.Add(ctx.RealIP(), ctx.Request().UserAgent(), user, ""); err != nil {
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

	if err := m.authLogService.Add(ctx.RealIP(), ctx.Request().UserAgent(), user, ""); err != nil {
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

	if err := m.authLogService.Add(ctx.RealIP(), ctx.Request().UserAgent(), user, ""); err != nil {
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
