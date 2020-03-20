package manager

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/ProtocolONE/auth1.protocol.one/pkg/database"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/models"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/service"
	"github.com/globalsign/mgo"
	"github.com/globalsign/mgo/bson"
	"github.com/labstack/echo/v4"
	"github.com/ory/hydra-client-go/client/admin"
	models2 "github.com/ory/hydra-client-go/models"
	"github.com/pkg/errors"
)

var (
	SocialAccountCanLink = "link"
	SocialAccountSuccess = "success"
	SocialAccountError   = "error"
)

var ErrAlreadyLinked = errors.New("account already linked to social")

// LoginManagerInterface describes of methods for the manager.
type LoginManagerInterface interface {

	// ForwardUrl returns url for forwarding user to id provider
	ForwardUrl(challenge, provider, domain, launcher string) (string, error)

	// Callback handles auth_code returned by id provider
	Callback(ctx echo.Context, provider, code, state, domain string) (string, error)

	// Providers returns list of available id providers for authentication
	Providers(challenge string) ([]*models.AppIdentityProvider, error)

	// Profile returns user profile attached to token
	Profile(token string) (*models.UserIdentitySocial, error)

	// Link links user profile attached to token with actual user in db
	Link(token string, userID bson.ObjectId, app *models.Application) error

	// Check verifies that provided token correct
	Check(token string) bool
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
		authLogService:          service.NewAuthLogService(h, r.GeoIpService()),
		identityProviderService: service.NewAppIdentityProviderService(),
	}

	return m
}

type State struct {
	Challenge string `json:"challenge`
	Launcher  string `json:"launcher"`
}

func DecodeState(state string) (*State, error) {
	data, err := base64.StdEncoding.DecodeString(state)
	if err != nil {
		return nil, errors.Wrap(err, "unable to decode state param")
	}

	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, errors.Wrap(err, "unable to unmarshal state")
	}
	return &s, nil
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
	req, err := m.r.HydraAdminApi().GetLoginRequest(&admin.GetLoginRequestParams{LoginChallenge: challenge, Context: context.TODO()})
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

func (m *LoginManager) Callback(ctx echo.Context, provider, code, state, domain string) (string, error) {
	s, err := DecodeState(state)
	if err != nil {
		return "", err
	}

	req, err := m.r.HydraAdminApi().GetLoginRequest(&admin.GetLoginRequestParams{LoginChallenge: s.Challenge, Context: context.TODO()})
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

		if err := m.authLogService.Add(ctx, service.ActionAuth, userIdentity, app, ip); err != nil {
			return "", errors.Wrap(err, "unable to add auth log")
		}

		id := userIdentity.UserID.Hex()
		// TODO sucessfully login
		reqACL, err := m.r.HydraAdminApi().AcceptLoginRequest(&admin.AcceptLoginRequestParams{
			Context:        context.TODO(),
			LoginChallenge: s.Challenge,
			Body:           &models2.AcceptLoginRequest{Subject: &id, Remember: true, RememberFor: RememberTime},
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

func (m *LoginManager) ForwardUrl(challenge, provider, domain, launcher string) (string, error) {
	req, err := m.r.HydraAdminApi().GetLoginRequest(&admin.GetLoginRequestParams{LoginChallenge: challenge, Context: context.TODO()})
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

	return m.identityProviderService.GetAuthUrl(domain, ip, &State{Challenge: challenge, Launcher: launcher})
}

func (m *LoginManager) Check(token string) bool {
	var t SocialToken
	return m.r.OneTimeTokenService().Get(token, &t) == nil
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

	// check for already linked
	_, err := m.userIdentityService.FindByUser(app, ip, userID)
	if err != mgo.ErrNotFound {
		if err != nil {
			return errors.Wrap(err, "can't search user identity info")
		}
		return ErrAlreadyLinked
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
