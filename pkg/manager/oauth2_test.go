package manager

import (
	"github.com/ProtocolONE/auth1.protocol.one/pkg/config"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/mocks"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/models"
	"github.com/globalsign/mgo"
	"github.com/globalsign/mgo/bson"
	"github.com/ory/hydra/sdk/go/hydra/client/admin"
	models2 "github.com/ory/hydra/sdk/go/hydra/models"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"testing"
)

func TestOauthManager(t *testing.T) {
	s := &mocks.MgoSession{}
	s.On("DB", mock.Anything).Return(&mgo.Database{})
	m := NewOauthManager(s, &mocks.InternalRegistry{}, &config.Session{Name: ""}, &config.Hydra{}, nil)
	assert.Implements(t, (*OauthManagerInterface)(nil), m)
}

func TestCheckAuthReturnErrorWithUnableToGetLoginRequest(t *testing.T) {
	h := &mocks.HydraAdminApi{}
	r := &mocks.InternalRegistry{}

	h.On("GetLoginRequest", mock.Anything).Return(nil, errors.New(""))
	r.On("HydraAdminApi").Return(h)

	m := &OauthManager{r: r}
	_, _, _, _, err := m.CheckAuth(getContext(), &models.Oauth2LoginForm{Challenge: "login_challenge"})
	assert.NotNil(t, err)
	assert.Equal(t, "common", err.Code)
	assert.Equal(t, models.ErrorLoginChallenge, err.Message)
}

func TestCheckAuthReturnErrorWithIncorrectClient(t *testing.T) {
	app := &mocks.ApplicationServiceInterface{}
	h := &mocks.HydraAdminApi{}
	r := &mocks.InternalRegistry{}

	h.On("GetLoginRequest", mock.Anything).Return(&admin.GetLoginRequestOK{Payload: &models2.LoginRequest{Client: &models2.Client{ClientID: bson.NewObjectId().Hex()}}}, nil)
	app.On("Get", mock.Anything).Return(nil, errors.New(""))
	r.On("HydraAdminApi").Return(h)
	r.On("ApplicationService").Return(app)

	m := &OauthManager{r: r}
	_, _, _, _, err := m.CheckAuth(getContext(), &models.Oauth2LoginForm{Challenge: "login_challenge"})
	assert.NotNil(t, err)
	assert.Equal(t, "client_id", err.Code)
	assert.Equal(t, models.ErrorClientIdIncorrect, err.Message)
}

func TestCheckAuthReturnErrorWithUnableToSetClientIdToSession(t *testing.T) {
	app := &mocks.ApplicationServiceInterface{}
	h := &mocks.HydraAdminApi{}
	ip := &mocks.AppIdentityProviderServiceInterface{}
	sess := &mocks.SessionService{}
	r := &mocks.InternalRegistry{}

	clientId := bson.NewObjectId().Hex()
	h.On("GetLoginRequest", mock.Anything).Return(&admin.GetLoginRequestOK{Payload: &models2.LoginRequest{Client: &models2.Client{ClientID: clientId}}}, nil)
	app.On("Get", mock.Anything).Return(&models.Application{}, nil)
	ip.On("FindByType", mock.Anything, models.AppIdentityProviderTypeSocial).Return([]*models.AppIdentityProvider{{}})
	sess.On("Set", mock.Anything, clientIdSessionKey, mock.Anything).Return(errors.New(""))
	r.On("HydraAdminApi").Return(h)
	r.On("ApplicationService").Return(app)

	m := &OauthManager{
		r:                       r,
		identityProviderService: ip,
		session:                 sess,
	}
	cid, _, _, _, err := m.CheckAuth(getContext(), &models.Oauth2LoginForm{Challenge: "login_challenge"})
	assert.NotNil(t, err)
	assert.Equal(t, "common", err.Code)
	assert.Equal(t, models.ErrorUnknownError, err.Message)
	assert.Equal(t, "", cid)
}

func TestCheckAuthReturnSuccessWithEmptySubject(t *testing.T) {
	app := &mocks.ApplicationServiceInterface{}
	h := &mocks.HydraAdminApi{}
	ip := &mocks.AppIdentityProviderServiceInterface{}
	sess := &mocks.SessionService{}
	r := &mocks.InternalRegistry{}

	clientId := bson.NewObjectId().Hex()
	h.On("GetLoginRequest", mock.Anything).Return(&admin.GetLoginRequestOK{Payload: &models2.LoginRequest{Client: &models2.Client{ClientID: clientId}}}, nil)
	app.On("Get", mock.Anything).Return(&models.Application{}, nil)
	ip.On("FindByType", mock.Anything, models.AppIdentityProviderTypeSocial).Return([]*models.AppIdentityProvider{{}})
	sess.On("Set", mock.Anything, clientIdSessionKey, mock.Anything).Return(nil)
	r.On("HydraAdminApi").Return(h)
	r.On("ApplicationService").Return(app)

	m := &OauthManager{
		r:                       r,
		identityProviderService: ip,
		session:                 sess,
	}
	cid, user, providers, url, err := m.CheckAuth(getContext(), &models.Oauth2LoginForm{Challenge: "login_challenge"})
	assert.Nil(t, err)
	assert.Equal(t, clientId, cid)
	assert.Nil(t, user)
	assert.Equal(t, []*models.AppIdentityProvider{{}}, providers)
	assert.Equal(t, "", url)
}

func TestCheckAuthReturnErrorWithUnableToSetRememberToSession(t *testing.T) {
	app := &mocks.ApplicationServiceInterface{}
	h := &mocks.HydraAdminApi{}
	ip := &mocks.AppIdentityProviderServiceInterface{}
	sess := &mocks.SessionService{}
	r := &mocks.InternalRegistry{}

	clientId := bson.NewObjectId().Hex()
	h.On("GetLoginRequest", mock.Anything).Return(&admin.GetLoginRequestOK{Payload: &models2.LoginRequest{Client: &models2.Client{ClientID: clientId}, Subject: "subj"}}, nil)
	app.On("Get", mock.Anything).Return(&models.Application{}, nil)
	ip.On("FindByType", mock.Anything, models.AppIdentityProviderTypeSocial).Return([]*models.AppIdentityProvider{{}})
	sess.On("Set", mock.Anything, clientIdSessionKey, mock.Anything).Return(nil)
	sess.On("Set", mock.Anything, loginRememberKey, mock.Anything).Return(errors.New(""))
	r.On("HydraAdminApi").Return(h)
	r.On("ApplicationService").Return(app)

	m := &OauthManager{
		r:                       r,
		identityProviderService: ip,
		session:                 sess,
	}
	cid, _, _, _, err := m.CheckAuth(getContext(), &models.Oauth2LoginForm{Challenge: "login_challenge"})
	assert.NotNil(t, err)
	assert.Equal(t, "common", err.Code)
	assert.Equal(t, models.ErrorUnknownError, err.Message)
	assert.Equal(t, "", cid)
}

func TestCheckAuthReturnErrorWithUnableToAcceptLoginRequest(t *testing.T) {
	app := &mocks.ApplicationServiceInterface{}
	h := &mocks.HydraAdminApi{}
	ip := &mocks.AppIdentityProviderServiceInterface{}
	sess := &mocks.SessionService{}
	r := &mocks.InternalRegistry{}

	clientId := bson.NewObjectId().Hex()
	h.On("GetLoginRequest", mock.Anything).Return(&admin.GetLoginRequestOK{Payload: &models2.LoginRequest{Client: &models2.Client{ClientID: clientId}, Subject: "subj", Skip: true}}, nil)
	app.On("Get", mock.Anything).Return(&models.Application{}, nil)
	ip.On("FindByType", mock.Anything, models.AppIdentityProviderTypeSocial).Return([]*models.AppIdentityProvider{{}})
	sess.On("Set", mock.Anything, clientIdSessionKey, mock.Anything).Return(nil)
	sess.On("Set", mock.Anything, loginRememberKey, mock.Anything).Return(nil)
	h.On("AcceptLoginRequest", mock.Anything).Return(nil, errors.New(""))
	r.On("HydraAdminApi").Return(h)
	r.On("ApplicationService").Return(app)

	m := &OauthManager{
		r:                       r,
		identityProviderService: ip,
		session:                 sess,
	}
	cid, user, providers, url, err := m.CheckAuth(getContext(), &models.Oauth2LoginForm{Challenge: "login_challenge"})
	assert.NotNil(t, err)
	assert.Equal(t, "common", err.Code)
	assert.Equal(t, models.ErrorUnknownError, err.Message)
	assert.Equal(t, clientId, cid)
	assert.Nil(t, user)
	assert.Nil(t, providers)
	assert.Equal(t, "", url)
}

func TestCheckAuthReturnUrlForSkipStep(t *testing.T) {
	app := &mocks.ApplicationServiceInterface{}
	h := &mocks.HydraAdminApi{}
	ip := &mocks.AppIdentityProviderServiceInterface{}
	sess := &mocks.SessionService{}
	r := &mocks.InternalRegistry{}

	clientId := bson.NewObjectId().Hex()
	h.On("GetLoginRequest", mock.Anything).Return(&admin.GetLoginRequestOK{Payload: &models2.LoginRequest{Client: &models2.Client{ClientID: clientId}, Subject: "subj", Skip: true}}, nil)
	app.On("Get", mock.Anything).Return(&models.Application{}, nil)
	ip.On("FindByType", mock.Anything, models.AppIdentityProviderTypeSocial).Return([]*models.AppIdentityProvider{{}})
	sess.On("Set", mock.Anything, clientIdSessionKey, mock.Anything).Return(nil)
	sess.On("Set", mock.Anything, loginRememberKey, mock.Anything).Return(nil)
	h.On("AcceptLoginRequest", mock.Anything).Return(&admin.AcceptLoginRequestOK{Payload: &models2.RequestHandlerResponse{RedirectTo: "url"}}, nil)
	r.On("HydraAdminApi").Return(h)
	r.On("ApplicationService").Return(app)

	m := &OauthManager{
		r:                       r,
		identityProviderService: ip,
		session:                 sess,
	}
	cid, user, providers, url, err := m.CheckAuth(getContext(), &models.Oauth2LoginForm{Challenge: "login_challenge"})
	assert.Nil(t, err)
	assert.Equal(t, clientId, cid)
	assert.Nil(t, user)
	assert.Nil(t, providers)
	assert.Equal(t, "url", url)
}

func TestCheckAuthReturnErrorWithUnableToGetUser(t *testing.T) {
	app := &mocks.ApplicationServiceInterface{}
	h := &mocks.HydraAdminApi{}
	ip := &mocks.AppIdentityProviderServiceInterface{}
	sess := &mocks.SessionService{}
	us := &mocks.UserServiceInterface{}
	r := &mocks.InternalRegistry{}

	clientId := bson.NewObjectId().Hex()
	h.On("GetLoginRequest", mock.Anything).Return(&admin.GetLoginRequestOK{Payload: &models2.LoginRequest{Client: &models2.Client{ClientID: clientId}, Subject: bson.NewObjectId().Hex(), Skip: false}}, nil)
	app.On("Get", mock.Anything).Return(&models.Application{}, nil)
	ip.On("FindByType", mock.Anything, models.AppIdentityProviderTypeSocial).Return([]*models.AppIdentityProvider{{}})
	sess.On("Set", mock.Anything, clientIdSessionKey, mock.Anything).Return(nil)
	sess.On("Set", mock.Anything, loginRememberKey, mock.Anything).Return(nil)
	us.On("Get", mock.Anything).Return(nil, errors.New(""))
	r.On("HydraAdminApi").Return(h)
	r.On("ApplicationService").Return(app)

	m := &OauthManager{
		r:                       r,
		identityProviderService: ip,
		session:                 sess,
		userService:             us,
	}
	cid, user, providers, url, err := m.CheckAuth(getContext(), &models.Oauth2LoginForm{Challenge: "login_challenge"})
	assert.NotNil(t, err)
	assert.Equal(t, "common", err.Code)
	assert.Equal(t, models.ErrorUnknownError, err.Message)
	assert.Equal(t, clientId, cid)
	assert.Nil(t, user)
	assert.Nil(t, providers)
	assert.Equal(t, "", url)
}

func TestCheckAuthReturnUserWithoutSkip(t *testing.T) {
	app := &mocks.ApplicationServiceInterface{}
	h := &mocks.HydraAdminApi{}
	ip := &mocks.AppIdentityProviderServiceInterface{}
	sess := &mocks.SessionService{}
	us := &mocks.UserServiceInterface{}
	r := &mocks.InternalRegistry{}

	clientId := bson.NewObjectId().Hex()
	h.On("GetLoginRequest", mock.Anything).Return(&admin.GetLoginRequestOK{Payload: &models2.LoginRequest{Client: &models2.Client{ClientID: clientId}, Subject: bson.NewObjectId().Hex(), Skip: false}}, nil)
	app.On("Get", mock.Anything).Return(&models.Application{}, nil)
	ip.On("FindByType", mock.Anything, models.AppIdentityProviderTypeSocial).Return([]*models.AppIdentityProvider{{}})
	sess.On("Set", mock.Anything, clientIdSessionKey, mock.Anything).Return(nil)
	sess.On("Set", mock.Anything, loginRememberKey, mock.Anything).Return(nil)
	us.On("Get", mock.Anything).Return(&models.User{}, nil)
	r.On("HydraAdminApi").Return(h)
	r.On("ApplicationService").Return(app)

	m := &OauthManager{
		r:                       r,
		identityProviderService: ip,
		session:                 sess,
		userService:             us,
	}
	cid, user, providers, url, err := m.CheckAuth(getContext(), &models.Oauth2LoginForm{Challenge: "login_challenge"})
	assert.Nil(t, err)
	assert.Equal(t, clientId, cid)
	assert.Equal(t, &models.User{}, user)
	assert.Equal(t, []*models.AppIdentityProvider{{}}, providers)
	assert.Equal(t, "", url)
}

func TestAuthReturnErrorWithUnableToGetLoginRequest(t *testing.T) {
	h := &mocks.HydraAdminApi{}
	r := &mocks.InternalRegistry{}

	h.On("GetLoginRequest", mock.Anything).Return(nil, errors.New(""))
	r.On("HydraAdminApi").Return(h)

	m := &OauthManager{r: r}
	_, err := m.Auth(getContext(), &models.Oauth2LoginSubmitForm{Challenge: "login_challenge"})
	assert.NotNil(t, err)
	assert.Equal(t, "common", err.Code)
	assert.Equal(t, models.ErrorLoginChallenge, err.Message)
}

func TestAuthReturnErrorWithIncorrectToken(t *testing.T) {
	ott := &mocks.OneTimeTokenServiceInterface{}
	h := &mocks.HydraAdminApi{}
	r := &mocks.InternalRegistry{}

	h.On("GetLoginRequest", mock.Anything).Return(&admin.GetLoginRequestOK{Payload: &models2.LoginRequest{Client: &models2.Client{ClientID: bson.NewObjectId().Hex()}}}, nil)
	ott.On("Use", "invalid_auth_token", mock.Anything).Return(errors.New(""))
	r.On("HydraAdminApi").Return(h)
	r.On("OneTimeTokenService").Return(ott)

	m := &OauthManager{r: r}
	_, err := m.Auth(getContext(), &models.Oauth2LoginSubmitForm{Challenge: "login_challenge", Token: "invalid_auth_token"})
	assert.NotNil(t, err)
	assert.Equal(t, "common", err.Code)
	assert.Equal(t, models.ErrorCannotUseToken, err.Message)
}

func TestAuthReturnErrorWithIncorrectClient(t *testing.T) {
	app := &mocks.ApplicationServiceInterface{}
	ott := &mocks.OneTimeTokenServiceInterface{}
	h := &mocks.HydraAdminApi{}
	r := &mocks.InternalRegistry{}

	h.On("GetLoginRequest", mock.Anything).Return(&admin.GetLoginRequestOK{Payload: &models2.LoginRequest{Client: &models2.Client{ClientID: bson.NewObjectId().Hex()}}}, nil)
	ott.On("Use", "invalid_auth_token", mock.Anything).Return(nil)
	app.On("Get", mock.Anything).Return(nil, errors.New(""))
	r.On("HydraAdminApi").Return(h)
	r.On("ApplicationService").Return(app)
	r.On("OneTimeTokenService").Return(ott)

	m := &OauthManager{r: r}
	_, err := m.Auth(getContext(), &models.Oauth2LoginSubmitForm{Challenge: "login_challenge"})
	assert.NotNil(t, err)
	assert.Equal(t, "client_id", err.Code)
	assert.Equal(t, models.ErrorClientIdIncorrect, err.Message)
}

func TestAuthReturnErrorWithUnavailableIdentityProvider(t *testing.T) {
	app := &mocks.ApplicationServiceInterface{}
	ott := &mocks.OneTimeTokenServiceInterface{}
	ip := &mocks.AppIdentityProviderServiceInterface{}
	h := &mocks.HydraAdminApi{}
	r := &mocks.InternalRegistry{}

	h.On("GetLoginRequest", mock.Anything).Return(&admin.GetLoginRequestOK{Payload: &models2.LoginRequest{Client: &models2.Client{ClientID: bson.NewObjectId().Hex()}}}, nil)
	ott.On("Use", "invalid_auth_token", mock.Anything).Return(nil)
	app.On("Get", mock.Anything).Return(&models.Application{}, nil)
	ip.On("FindByTypeAndName", mock.Anything, models.AppIdentityProviderTypePassword, models.AppIdentityProviderNameDefault).Return(nil)
	r.On("HydraAdminApi").Return(h)
	r.On("ApplicationService").Return(app)
	r.On("OneTimeTokenService").Return(ott)

	m := &OauthManager{
		r:                       r,
		identityProviderService: ip,
	}
	_, err := m.Auth(getContext(), &models.Oauth2LoginSubmitForm{Challenge: "login_challenge"})
	assert.NotNil(t, err)
	assert.Equal(t, "client_id", err.Code)
	assert.Equal(t, models.ErrorClientIdIncorrect, err.Message)
}

func TestAuthReturnErrorWithUnavailableUserIdentity(t *testing.T) {
	app := &mocks.ApplicationServiceInterface{}
	ott := &mocks.OneTimeTokenServiceInterface{}
	ip := &mocks.AppIdentityProviderServiceInterface{}
	uis := &mocks.UserIdentityServiceInterface{}
	h := &mocks.HydraAdminApi{}
	r := &mocks.InternalRegistry{}

	h.On("GetLoginRequest", mock.Anything).Return(&admin.GetLoginRequestOK{Payload: &models2.LoginRequest{Client: &models2.Client{ClientID: bson.NewObjectId().Hex()}}}, nil)
	ott.On("Use", "invalid_auth_token", mock.Anything).Return(nil)
	app.On("Get", mock.Anything).Return(&models.Application{}, nil)
	ip.On("FindByTypeAndName", mock.Anything, models.AppIdentityProviderTypePassword, models.AppIdentityProviderNameDefault).Return(&models.AppIdentityProvider{})
	uis.On("Get", mock.Anything, mock.Anything, "invalid_email").Return(nil, errors.New(""))
	r.On("HydraAdminApi").Return(h)
	r.On("ApplicationService").Return(app)
	r.On("OneTimeTokenService").Return(ott)

	m := &OauthManager{
		r:                       r,
		identityProviderService: ip,
		userIdentityService:     uis,
	}
	_, err := m.Auth(getContext(), &models.Oauth2LoginSubmitForm{Challenge: "login_challenge", Email: "invalid_email"})
	assert.NotNil(t, err)
	assert.Equal(t, "email", err.Code)
	assert.Equal(t, models.ErrorLoginIncorrect, err.Message)
}

func TestAuthReturnErrorWithComparePassword(t *testing.T) {
	app := &mocks.ApplicationServiceInterface{}
	ott := &mocks.OneTimeTokenServiceInterface{}
	ip := &mocks.AppIdentityProviderServiceInterface{}
	uis := &mocks.UserIdentityServiceInterface{}
	h := &mocks.HydraAdminApi{}
	r := &mocks.InternalRegistry{}

	passSettings := &models.PasswordSettings{Min: 1, Max: 8, RequireSpecial: false, RequireUpper: false, RequireNumber: false, BcryptCost: 4}

	h.On("GetLoginRequest", mock.Anything).Return(&admin.GetLoginRequestOK{Payload: &models2.LoginRequest{Client: &models2.Client{ClientID: bson.NewObjectId().Hex()}}}, nil)
	ott.On("Use", "invalid_auth_token", mock.Anything).Return(nil)
	app.On("Get", mock.Anything).Return(&models.Application{PasswordSettings: passSettings}, nil)
	ip.On("FindByTypeAndName", mock.Anything, models.AppIdentityProviderTypePassword, models.AppIdentityProviderNameDefault).Return(&models.AppIdentityProvider{})
	uis.On("Get", mock.Anything, mock.Anything, "email").Return(&models.UserIdentity{Credential: "1"}, nil)
	r.On("HydraAdminApi").Return(h)
	r.On("ApplicationService").Return(app)
	r.On("OneTimeTokenService").Return(ott)

	m := &OauthManager{
		r:                       r,
		identityProviderService: ip,
		userIdentityService:     uis,
	}
	_, err := m.Auth(getContext(), &models.Oauth2LoginSubmitForm{Challenge: "login_challenge", Email: "email", Password: "1234"})
	assert.NotNil(t, err)
	assert.Equal(t, "password", err.Code)
	assert.Equal(t, models.ErrorPasswordIncorrect, err.Message)
}

func TestAuthReturnErrorWithUnableToGetUser(t *testing.T) {
	app := &mocks.ApplicationServiceInterface{}
	ott := &mocks.OneTimeTokenServiceInterface{}
	ip := &mocks.AppIdentityProviderServiceInterface{}
	uis := &mocks.UserIdentityServiceInterface{}
	us := &mocks.UserServiceInterface{}
	h := &mocks.HydraAdminApi{}
	r := &mocks.InternalRegistry{}

	passSettings := &models.PasswordSettings{Min: 1, Max: 8, RequireSpecial: false, RequireUpper: false, RequireNumber: false, BcryptCost: 4}
	be := models.NewBcryptEncryptor(&models.CryptConfig{Cost: passSettings.BcryptCost})
	passHash, _ := be.Digest("1234")

	h.On("GetLoginRequest", mock.Anything).Return(&admin.GetLoginRequestOK{Payload: &models2.LoginRequest{Client: &models2.Client{ClientID: bson.NewObjectId().Hex()}}}, nil)
	ott.On("Use", "invalid_auth_token", mock.Anything).Return(nil)
	app.On("Get", mock.Anything).Return(&models.Application{PasswordSettings: passSettings}, nil)
	ip.On("FindByTypeAndName", mock.Anything, models.AppIdentityProviderTypePassword, models.AppIdentityProviderNameDefault).Return(&models.AppIdentityProvider{})
	uis.On("Get", mock.Anything, mock.Anything, "email").Return(&models.UserIdentity{Credential: passHash}, nil)
	us.On("Get", mock.Anything).Return(nil, errors.New(""))
	r.On("HydraAdminApi").Return(h)
	r.On("ApplicationService").Return(app)
	r.On("OneTimeTokenService").Return(ott)

	m := &OauthManager{
		r:                       r,
		identityProviderService: ip,
		userIdentityService:     uis,
		userService:             us,
	}
	_, err := m.Auth(getContext(), &models.Oauth2LoginSubmitForm{Challenge: "login_challenge", Email: "email", Password: "1234"})
	assert.NotNil(t, err)
	assert.Equal(t, "email", err.Code)
	assert.Equal(t, models.ErrorLoginIncorrect, err.Message)
}

func TestAuthReturnErrorWithUnableToUpdateUser(t *testing.T) {
	app := &mocks.ApplicationServiceInterface{}
	ott := &mocks.OneTimeTokenServiceInterface{}
	ip := &mocks.AppIdentityProviderServiceInterface{}
	uis := &mocks.UserIdentityServiceInterface{}
	us := &mocks.UserServiceInterface{}
	h := &mocks.HydraAdminApi{}
	r := &mocks.InternalRegistry{}

	passSettings := &models.PasswordSettings{Min: 1, Max: 8, RequireSpecial: false, RequireUpper: false, RequireNumber: false, BcryptCost: 4}
	be := models.NewBcryptEncryptor(&models.CryptConfig{Cost: passSettings.BcryptCost})
	passHash, _ := be.Digest("1234")

	h.On("GetLoginRequest", mock.Anything).Return(&admin.GetLoginRequestOK{Payload: &models2.LoginRequest{Client: &models2.Client{ClientID: bson.NewObjectId().Hex()}}}, nil)
	ott.On("Use", "invalid_auth_token", mock.Anything).Return(nil)
	app.On("Get", mock.Anything).Return(&models.Application{PasswordSettings: passSettings}, nil)
	ip.On("FindByTypeAndName", mock.Anything, models.AppIdentityProviderTypePassword, models.AppIdentityProviderNameDefault).Return(&models.AppIdentityProvider{})
	uis.On("Get", mock.Anything, mock.Anything, "email").Return(&models.UserIdentity{Credential: passHash}, nil)
	us.On("Get", mock.Anything).Return(&models.User{}, nil)
	us.On("Update", mock.Anything).Return(errors.New(""))
	r.On("HydraAdminApi").Return(h)
	r.On("ApplicationService").Return(app)
	r.On("OneTimeTokenService").Return(ott)

	m := &OauthManager{
		r:                       r,
		identityProviderService: ip,
		userIdentityService:     uis,
		userService:             us,
	}
	_, err := m.Auth(getContext(), &models.Oauth2LoginSubmitForm{Challenge: "login_challenge", Email: "email", Password: "1234"})
	assert.NotNil(t, err)
	assert.Equal(t, "common", err.Code)
	assert.Equal(t, models.ErrorUpdateUser, err.Message)
}

func TestAuthReturnErrorWithUnableToAddAuthLog(t *testing.T) {
	app := &mocks.ApplicationServiceInterface{}
	ott := &mocks.OneTimeTokenServiceInterface{}
	ip := &mocks.AppIdentityProviderServiceInterface{}
	uis := &mocks.UserIdentityServiceInterface{}
	us := &mocks.UserServiceInterface{}
	al := &mocks.AuthLogServiceInterface{}
	h := &mocks.HydraAdminApi{}
	r := &mocks.InternalRegistry{}

	passSettings := &models.PasswordSettings{Min: 1, Max: 8, RequireSpecial: false, RequireUpper: false, RequireNumber: false, BcryptCost: 4}
	be := models.NewBcryptEncryptor(&models.CryptConfig{Cost: passSettings.BcryptCost})
	passHash, _ := be.Digest("1234")

	h.On("GetLoginRequest", mock.Anything).Return(&admin.GetLoginRequestOK{Payload: &models2.LoginRequest{Client: &models2.Client{ClientID: bson.NewObjectId().Hex()}}}, nil)
	ott.On("Use", "invalid_auth_token", mock.Anything).Return(nil)
	app.On("Get", mock.Anything).Return(&models.Application{PasswordSettings: passSettings}, nil)
	ip.On("FindByTypeAndName", mock.Anything, models.AppIdentityProviderTypePassword, models.AppIdentityProviderNameDefault).Return(&models.AppIdentityProvider{})
	uis.On("Get", mock.Anything, mock.Anything, "email").Return(&models.UserIdentity{Credential: passHash}, nil)
	us.On("Get", mock.Anything).Return(&models.User{}, nil)
	us.On("Update", mock.Anything).Return(nil)
	al.On("Add", mock.Anything, mock.Anything, mock.Anything).Return(errors.New(""))
	r.On("HydraAdminApi").Return(h)
	r.On("ApplicationService").Return(app)
	r.On("OneTimeTokenService").Return(ott)

	m := &OauthManager{
		r:                       r,
		identityProviderService: ip,
		userIdentityService:     uis,
		userService:             us,
		authLogService:          al,
	}
	_, err := m.Auth(getContext(), &models.Oauth2LoginSubmitForm{Challenge: "login_challenge", Email: "email", Password: "1234"})
	assert.NotNil(t, err)
	assert.Equal(t, "common", err.Code)
	assert.Equal(t, models.ErrorAddAuthLog, err.Message)
}

func TestAuthReturnErrorWithUnableToSetSessionRemember(t *testing.T) {
	h := &mocks.HydraAdminApi{}
	s := &mocks.SessionService{}
	r := &mocks.InternalRegistry{}

	h.On("GetLoginRequest", mock.Anything).Return(&admin.GetLoginRequestOK{Payload: &models2.LoginRequest{Client: &models2.Client{ClientID: bson.NewObjectId().Hex()}, Subject: "subj"}}, nil)
	s.On("Set", mock.Anything, loginRememberKey, true).Return(errors.New(""))
	r.On("HydraAdminApi").Return(h)

	m := &OauthManager{
		r:       r,
		session: s,
	}
	_, err := m.Auth(getContext(), &models.Oauth2LoginSubmitForm{Challenge: "login_challenge", Remember: true, PreviousLogin: "subj"})
	assert.NotNil(t, err)
	assert.Equal(t, "common", err.Code)
	assert.Equal(t, models.ErrorUnknownError, err.Message)
}

func TestAuthReturnErrorWithUnableToAcceptLoginRequest(t *testing.T) {
	h := &mocks.HydraAdminApi{}
	s := &mocks.SessionService{}
	r := &mocks.InternalRegistry{}

	h.On("GetLoginRequest", mock.Anything).Return(&admin.GetLoginRequestOK{Payload: &models2.LoginRequest{Client: &models2.Client{ClientID: bson.NewObjectId().Hex()}, Subject: "subj"}}, nil)
	s.On("Set", mock.Anything, loginRememberKey, true).Return(nil)
	h.On("AcceptLoginRequest", mock.Anything).Return(nil, errors.New(""))
	r.On("HydraAdminApi").Return(h)

	m := &OauthManager{
		r:       r,
		session: s,
	}
	_, err := m.Auth(getContext(), &models.Oauth2LoginSubmitForm{Challenge: "login_challenge", Remember: true, PreviousLogin: "subj"})
	assert.NotNil(t, err)
	assert.Equal(t, "common", err.Code)
	assert.Equal(t, models.ErrorPasswordIncorrect, err.Message)
}

func TestAuthReturnUrlToConsentRequest(t *testing.T) {
	h := &mocks.HydraAdminApi{}
	s := &mocks.SessionService{}
	r := &mocks.InternalRegistry{}

	h.On("GetLoginRequest", mock.Anything).Return(&admin.GetLoginRequestOK{Payload: &models2.LoginRequest{Client: &models2.Client{ClientID: bson.NewObjectId().Hex()}, Subject: "subj"}}, nil)
	s.On("Set", mock.Anything, loginRememberKey, true).Return(nil)
	h.On("AcceptLoginRequest", mock.Anything).Return(&admin.AcceptLoginRequestOK{Payload: &models2.RequestHandlerResponse{RedirectTo: "url"}}, nil)
	r.On("HydraAdminApi").Return(h)

	m := &OauthManager{
		r:       r,
		session: s,
	}
	url, err := m.Auth(getContext(), &models.Oauth2LoginSubmitForm{Challenge: "login_challenge", Remember: true, PreviousLogin: "subj"})
	assert.Nil(t, err)
	assert.Equal(t, "url", url)
}

func TestGetScopes(t *testing.T) {
	m := &OauthManager{}
	scopes := []string{"openid", "offline"}
	assert.Equal(t, scopes, m.GetScopes(append(scopes, "offline")))
}

func TestConsentReturnErrorWithUnableToGetConsentRequest(t *testing.T) {
	h := &mocks.HydraAdminApi{}
	r := &mocks.InternalRegistry{}

	h.On("GetConsentRequest", mock.Anything).Return(nil, errors.New(""))
	r.On("HydraAdminApi").Return(h)

	m := &OauthManager{r: r}
	_, err := m.Consent(getContext(), &models.Oauth2ConsentForm{Challenge: "consent_challenge"})
	assert.NotNil(t, err)
	assert.Equal(t, "common", err.Code)
	assert.Equal(t, models.ErrorUnknownError, err.Message)
}

func TestConsentReturnErrorWithUnableToSetClientToSession(t *testing.T) {
	h := &mocks.HydraAdminApi{}
	s := &mocks.SessionService{}
	r := &mocks.InternalRegistry{}

	h.On("GetConsentRequest", mock.Anything).Return(&admin.GetConsentRequestOK{Payload: &models2.ConsentRequest{Client: &models2.Client{ClientID: bson.NewObjectId().Hex()}}}, nil)
	s.On("Set", mock.Anything, clientIdSessionKey, mock.Anything).Return(errors.New(""))
	r.On("HydraAdminApi").Return(h)

	m := &OauthManager{
		r:       r,
		session: s,
	}
	_, err := m.Consent(getContext(), &models.Oauth2ConsentForm{Challenge: "consent_challenge"})
	assert.NotNil(t, err)
	assert.Equal(t, "common", err.Code)
	assert.Equal(t, models.ErrorUnknownError, err.Message)
}

func TestConsentReturnScopes(t *testing.T) {
	h := &mocks.HydraAdminApi{}
	s := &mocks.SessionService{}
	r := &mocks.InternalRegistry{}

	h.On("GetConsentRequest", mock.Anything).Return(&admin.GetConsentRequestOK{Payload: &models2.ConsentRequest{Client: &models2.Client{ClientID: bson.NewObjectId().Hex()}}}, nil)
	s.On("Set", mock.Anything, clientIdSessionKey, mock.Anything).Return(nil)
	r.On("HydraAdminApi").Return(h)

	m := &OauthManager{
		r:       r,
		session: s,
	}
	scopes, err := m.Consent(getContext(), &models.Oauth2ConsentForm{Challenge: "consent_challenge"})
	assert.Nil(t, err)
	assert.Equal(t, []string{"openid", "offline"}, scopes)
}

func TestConsentSubmitReturnErrorWithUnableToGetConsentRequest(t *testing.T) {
	h := &mocks.HydraAdminApi{}
	r := &mocks.InternalRegistry{}

	h.On("GetConsentRequest", mock.Anything).Return(nil, errors.New(""))
	r.On("HydraAdminApi").Return(h)

	m := &OauthManager{r: r}
	_, err := m.ConsentSubmit(getContext(), &models.Oauth2ConsentSubmitForm{Challenge: "consent_challenge"})
	assert.NotNil(t, err)
	assert.Equal(t, "common", err.Code)
	assert.Equal(t, models.ErrorUnknownError, err.Message)
}

func TestConsentSubmitReturnErrorWithUnableToGetUser(t *testing.T) {
	h := &mocks.HydraAdminApi{}
	s := &mocks.SessionService{}
	us := &mocks.UserServiceInterface{}
	r := &mocks.InternalRegistry{}

	h.On("GetConsentRequest", mock.Anything).Return(&admin.GetConsentRequestOK{Payload: &models2.ConsentRequest{Client: &models2.Client{ClientID: bson.NewObjectId().Hex()}, Subject: bson.NewObjectId().Hex()}}, nil)
	s.On("Set", mock.Anything, clientIdSessionKey, mock.Anything).Return(nil)
	us.On("Get", mock.Anything).Return(nil, errors.New(""))
	r.On("HydraAdminApi").Return(h)

	m := &OauthManager{
		r:           r,
		session:     s,
		userService: us,
	}
	_, err := m.ConsentSubmit(getContext(), &models.Oauth2ConsentSubmitForm{Challenge: "consent_challenge"})
	assert.NotNil(t, err)
	assert.Equal(t, "email", err.Code)
	assert.Equal(t, models.ErrorLoginIncorrect, err.Message)
}

func TestConsentSubmitReturnErrorWithUnableToGetRemember(t *testing.T) {
	h := &mocks.HydraAdminApi{}
	s := &mocks.SessionService{}
	us := &mocks.UserServiceInterface{}
	r := &mocks.InternalRegistry{}

	h.On("GetConsentRequest", mock.Anything).Return(&admin.GetConsentRequestOK{Payload: &models2.ConsentRequest{Client: &models2.Client{ClientID: bson.NewObjectId().Hex()}, Subject: bson.NewObjectId().Hex(), Skip: true}}, nil)
	s.On("Set", mock.Anything, clientIdSessionKey, mock.Anything).Return(nil)
	us.On("Get", mock.Anything).Return(&models.User{}, nil)
	s.On("Get", mock.Anything, loginRememberKey).Return(nil, errors.New(""))
	r.On("HydraAdminApi").Return(h)

	m := &OauthManager{
		r:           r,
		session:     s,
		userService: us,
	}
	_, err := m.ConsentSubmit(getContext(), &models.Oauth2ConsentSubmitForm{Challenge: "consent_challenge"})
	assert.NotNil(t, err)
	assert.Equal(t, "common", err.Code)
	assert.Equal(t, models.ErrorUnknownError, err.Message)
}

func TestConsentSubmitReturnErrorWithUnableToAcceptConsent(t *testing.T) {
	h := &mocks.HydraAdminApi{}
	s := &mocks.SessionService{}
	us := &mocks.UserServiceInterface{}
	r := &mocks.InternalRegistry{}

	h.On("GetConsentRequest", mock.Anything).Return(&admin.GetConsentRequestOK{Payload: &models2.ConsentRequest{Client: &models2.Client{ClientID: bson.NewObjectId().Hex()}, Subject: bson.NewObjectId().Hex()}}, nil)
	s.On("Set", mock.Anything, clientIdSessionKey, mock.Anything).Return(nil)
	us.On("Get", mock.Anything).Return(&models.User{}, nil)
	h.On("AcceptConsentRequest", mock.Anything).Return(nil, errors.New(""))
	r.On("HydraAdminApi").Return(h)

	m := &OauthManager{
		r:           r,
		session:     s,
		userService: us,
	}
	_, err := m.ConsentSubmit(getContext(), &models.Oauth2ConsentSubmitForm{Challenge: "consent_challenge"})
	assert.NotNil(t, err)
	assert.Equal(t, "common", err.Code)
	assert.Equal(t, models.ErrorUnknownError, err.Message)
}

func TestConsentSubmitReturnUrlToRedirect(t *testing.T) {
	h := &mocks.HydraAdminApi{}
	s := &mocks.SessionService{}
	us := &mocks.UserServiceInterface{}
	r := &mocks.InternalRegistry{}

	h.On("GetConsentRequest", mock.Anything).Return(&admin.GetConsentRequestOK{Payload: &models2.ConsentRequest{Client: &models2.Client{ClientID: bson.NewObjectId().Hex()}, Subject: bson.NewObjectId().Hex()}}, nil)
	s.On("Set", mock.Anything, clientIdSessionKey, mock.Anything).Return(nil)
	us.On("Get", mock.Anything).Return(&models.User{}, nil)
	h.On("AcceptConsentRequest", mock.Anything).Return(&admin.AcceptConsentRequestOK{Payload: &models2.RequestHandlerResponse{RedirectTo: "url"}}, nil)
	r.On("HydraAdminApi").Return(h)

	m := &OauthManager{
		r:           r,
		session:     s,
		userService: us,
	}
	url, err := m.ConsentSubmit(getContext(), &models.Oauth2ConsentSubmitForm{Challenge: "consent_challenge"})
	assert.Nil(t, err)
	assert.Equal(t, "url", url)
}

func TestIntrospectReturnErrorWithIncorrectClient(t *testing.T) {
	app := &mocks.ApplicationServiceInterface{}
	r := &mocks.InternalRegistry{}

	app.On("Get", mock.Anything).Return(nil, errors.New(""))
	r.On("ApplicationService").Return(app)

	m := &OauthManager{r: r}
	_, err := m.Introspect(getContext(), &models.Oauth2IntrospectForm{ClientID: bson.NewObjectId().Hex()})
	assert.NotNil(t, err)
	assert.Equal(t, "client_id", err.Code)
	assert.Equal(t, models.ErrorClientIdIncorrect, err.Message)
}

func TestIntrospectReturnErrorWithIncorrectSecret(t *testing.T) {
	app := &mocks.ApplicationServiceInterface{}
	r := &mocks.InternalRegistry{}

	app.On("Get", mock.Anything).Return(&models.Application{AuthSecret: "1"}, nil)
	r.On("ApplicationService").Return(app)

	m := &OauthManager{r: r}
	_, err := m.Introspect(getContext(), &models.Oauth2IntrospectForm{ClientID: bson.NewObjectId().Hex(), Secret: "2"})
	assert.NotNil(t, err)
	assert.Equal(t, "secret", err.Code)
	assert.Equal(t, models.ErrorUnknownError, err.Message)
}

func TestIntrospectReturnErrorWithUnableToIntrospect(t *testing.T) {
	app := &mocks.ApplicationServiceInterface{}
	h := &mocks.HydraAdminApi{}
	r := &mocks.InternalRegistry{}

	app.On("Get", mock.Anything).Return(&models.Application{AuthSecret: "1"}, nil)
	h.On("IntrospectOAuth2Token", mock.Anything, mock.Anything).Return(nil, errors.New(""))
	r.On("ApplicationService").Return(app)
	r.On("HydraAdminApi").Return(h)

	m := &OauthManager{r: r}
	_, err := m.Introspect(getContext(), &models.Oauth2IntrospectForm{ClientID: bson.NewObjectId().Hex(), Secret: "1"})
	assert.NotNil(t, err)
	assert.Equal(t, "common", err.Code)
	assert.Equal(t, models.ErrorUnknownError, err.Message)
}

func TestIntrospectReturnSuccess(t *testing.T) {
	app := &mocks.ApplicationServiceInterface{}
	h := &mocks.HydraAdminApi{}
	r := &mocks.InternalRegistry{}

	app.On("Get", mock.Anything).Return(&models.Application{AuthSecret: "1"}, nil)
	h.On("IntrospectOAuth2Token", mock.Anything, mock.Anything).Return(&admin.IntrospectOAuth2TokenOK{Payload: &models2.Introspection{}}, nil)
	r.On("ApplicationService").Return(app)
	r.On("HydraAdminApi").Return(h)

	m := &OauthManager{r: r}
	result, err := m.Introspect(getContext(), &models.Oauth2IntrospectForm{ClientID: bson.NewObjectId().Hex(), Secret: "1"})
	assert.Nil(t, err)
	assert.Equal(t, &models.Oauth2TokenIntrospection{}, result)
}

func TestSignUpReturnErrorWithUnableToSetRememberToSession(t *testing.T) {
	s := &mocks.SessionService{}

	s.On("Set", mock.Anything, loginRememberKey, true).Return(errors.New(""))

	m := &OauthManager{session: s}
	_, err := m.SignUp(getContext(), &models.Oauth2SignUpForm{Remember: true})
	assert.NotNil(t, err)
	assert.Equal(t, "common", err.Code)
	assert.Equal(t, models.ErrorUnknownError, err.Message)
}

func TestSignUpReturnErrorWithUnableToGetClientFromSession(t *testing.T) {
	s := &mocks.SessionService{}
	app := &mocks.ApplicationServiceInterface{}
	r := &mocks.InternalRegistry{}

	s.On("Set", mock.Anything, loginRememberKey, true).Return(nil)
	s.On("Get", mock.Anything, clientIdSessionKey).Return(nil, errors.New(""))
	r.On("ApplicationService").Return(app)

	m := &OauthManager{
		r:       r,
		session: s,
	}
	_, err := m.SignUp(getContext(), &models.Oauth2SignUpForm{Remember: true})
	assert.NotNil(t, err)
	assert.Equal(t, "common", err.Code)
	assert.Equal(t, models.ErrorUnknownError, err.Message)
}

func TestSignUpReturnErrorWithUnableToGetApplication(t *testing.T) {
	s := &mocks.SessionService{}
	app := &mocks.ApplicationServiceInterface{}
	r := &mocks.InternalRegistry{}

	s.On("Set", mock.Anything, loginRememberKey, true).Return(nil)
	s.On("Get", mock.Anything, clientIdSessionKey).Return(bson.NewObjectId().Hex(), nil)
	app.On("Get", mock.Anything).Return(nil, errors.New(""))
	r.On("ApplicationService").Return(app)

	m := &OauthManager{
		r:       r,
		session: s,
	}
	_, err := m.SignUp(getContext(), &models.Oauth2SignUpForm{Remember: true})
	assert.NotNil(t, err)
	assert.Equal(t, "client_id", err.Code)
	assert.Equal(t, models.ErrorClientIdIncorrect, err.Message)
}

func TestSignUpReturnErrorWithInvalidPassword(t *testing.T) {
	s := &mocks.SessionService{}
	app := &mocks.ApplicationServiceInterface{}
	r := &mocks.InternalRegistry{}

	passSettings := &models.PasswordSettings{Min: 2, Max: 8, RequireSpecial: false, RequireUpper: false, RequireNumber: false}
	s.On("Set", mock.Anything, loginRememberKey, true).Return(nil)
	s.On("Get", mock.Anything, clientIdSessionKey).Return(bson.NewObjectId().Hex(), nil)
	app.On("Get", mock.Anything).Return(&models.Application{PasswordSettings: passSettings}, nil)
	r.On("ApplicationService").Return(app)

	m := &OauthManager{
		r:       r,
		session: s,
	}
	_, err := m.SignUp(getContext(), &models.Oauth2SignUpForm{Remember: true, Password: "1"})
	assert.NotNil(t, err)
	assert.Equal(t, "password", err.Code)
	assert.Equal(t, models.ErrorPasswordIncorrect, err.Message)
}

func TestSignUpReturnErrorWithUnableToGetLoginChallenge(t *testing.T) {
	s := &mocks.SessionService{}
	app := &mocks.ApplicationServiceInterface{}
	h := &mocks.HydraAdminApi{}
	r := &mocks.InternalRegistry{}

	passSettings := &models.PasswordSettings{Min: 2, Max: 8, RequireSpecial: false, RequireUpper: false, RequireNumber: false}
	s.On("Set", mock.Anything, loginRememberKey, true).Return(nil)
	s.On("Get", mock.Anything, clientIdSessionKey).Return(bson.NewObjectId().Hex(), nil)
	app.On("Get", mock.Anything).Return(&models.Application{PasswordSettings: passSettings}, nil)
	h.On("GetLoginRequest", mock.Anything).Return(nil, errors.New(""))
	r.On("ApplicationService").Return(app)
	r.On("HydraAdminApi").Return(h)

	m := &OauthManager{
		r:       r,
		session: s,
	}
	_, err := m.SignUp(getContext(), &models.Oauth2SignUpForm{Remember: true, Password: "11", Challenge: "login_challenge"})
	assert.NotNil(t, err)
	assert.Equal(t, "common", err.Code)
	assert.Equal(t, models.ErrorLoginChallenge, err.Message)
}

func TestSignUpReturnErrorWithDifferentClientId(t *testing.T) {
	s := &mocks.SessionService{}
	app := &mocks.ApplicationServiceInterface{}
	h := &mocks.HydraAdminApi{}
	r := &mocks.InternalRegistry{}

	passSettings := &models.PasswordSettings{Min: 2, Max: 8, RequireSpecial: false, RequireUpper: false, RequireNumber: false}
	s.On("Set", mock.Anything, loginRememberKey, true).Return(nil)
	s.On("Get", mock.Anything, clientIdSessionKey).Return(bson.NewObjectId().Hex(), nil)
	app.On("Get", mock.Anything).Return(&models.Application{PasswordSettings: passSettings}, nil)
	h.On("GetLoginRequest", mock.Anything).Return(&admin.GetLoginRequestOK{Payload: &models2.LoginRequest{Client: &models2.Client{ClientID: bson.NewObjectId().Hex()}}}, nil)
	r.On("ApplicationService").Return(app)
	r.On("HydraAdminApi").Return(h)

	m := &OauthManager{
		r:       r,
		session: s,
	}
	_, err := m.SignUp(getContext(), &models.Oauth2SignUpForm{Remember: true, Password: "11", Challenge: "login_challenge"})
	assert.NotNil(t, err)
	assert.Equal(t, "client_id", err.Code)
	assert.Equal(t, models.ErrorClientIdIncorrect, err.Message)
}

func TestSignUpReturnErrorWithUnavailableIdentityProvider(t *testing.T) {
	s := &mocks.SessionService{}
	app := &mocks.ApplicationServiceInterface{}
	h := &mocks.HydraAdminApi{}
	ip := &mocks.AppIdentityProviderServiceInterface{}
	r := &mocks.InternalRegistry{}

	clientId := bson.NewObjectId().Hex()
	passSettings := &models.PasswordSettings{Min: 2, Max: 8, RequireSpecial: false, RequireUpper: false, RequireNumber: false}
	s.On("Set", mock.Anything, loginRememberKey, true).Return(nil)
	s.On("Get", mock.Anything, clientIdSessionKey).Return(clientId, nil)
	app.On("Get", mock.Anything).Return(&models.Application{PasswordSettings: passSettings}, nil)
	h.On("GetLoginRequest", mock.Anything).Return(&admin.GetLoginRequestOK{Payload: &models2.LoginRequest{Client: &models2.Client{ClientID: clientId}}}, nil)
	ip.On("FindByTypeAndName", mock.Anything, models.AppIdentityProviderTypePassword, models.AppIdentityProviderNameDefault).Return(nil)
	r.On("ApplicationService").Return(app)
	r.On("HydraAdminApi").Return(h)

	m := &OauthManager{
		r:                       r,
		session:                 s,
		identityProviderService: ip,
	}
	_, err := m.SignUp(getContext(), &models.Oauth2SignUpForm{Remember: true, Password: "11", Challenge: "login_challenge"})
	assert.NotNil(t, err)
	assert.Equal(t, "client_id", err.Code)
	assert.Equal(t, models.ErrorProviderIdIncorrect, err.Message)
}

func TestSignUpReturnErrorWithUnableToGetUserIdentity(t *testing.T) {
	s := &mocks.SessionService{}
	app := &mocks.ApplicationServiceInterface{}
	h := &mocks.HydraAdminApi{}
	ip := &mocks.AppIdentityProviderServiceInterface{}
	ui := &mocks.UserIdentityServiceInterface{}
	r := &mocks.InternalRegistry{}

	clientId := bson.NewObjectId().Hex()
	passSettings := &models.PasswordSettings{Min: 2, Max: 8, RequireSpecial: false, RequireUpper: false, RequireNumber: false}
	s.On("Set", mock.Anything, loginRememberKey, true).Return(nil)
	s.On("Get", mock.Anything, clientIdSessionKey).Return(clientId, nil)
	app.On("Get", mock.Anything).Return(&models.Application{PasswordSettings: passSettings}, nil)
	h.On("GetLoginRequest", mock.Anything).Return(&admin.GetLoginRequestOK{Payload: &models2.LoginRequest{Client: &models2.Client{ClientID: clientId}}}, nil)
	ip.On("FindByTypeAndName", mock.Anything, models.AppIdentityProviderTypePassword, models.AppIdentityProviderNameDefault).Return(&models.AppIdentityProvider{})
	ui.On("Get", mock.Anything, mock.Anything, "email").Return(&models.UserIdentity{}, nil)
	r.On("ApplicationService").Return(app)
	r.On("HydraAdminApi").Return(h)

	m := &OauthManager{
		r:                       r,
		session:                 s,
		identityProviderService: ip,
		userIdentityService:     ui,
	}
	_, err := m.SignUp(getContext(), &models.Oauth2SignUpForm{Remember: true, Password: "11", Challenge: "login_challenge", Email: "email"})
	assert.NotNil(t, err)
	assert.Equal(t, "email", err.Code)
	assert.Equal(t, models.ErrorLoginIncorrect, err.Message)
}

func TestSignUpReturnErrorWithEncryptPassword(t *testing.T) {
	s := &mocks.SessionService{}
	app := &mocks.ApplicationServiceInterface{}
	h := &mocks.HydraAdminApi{}
	ip := &mocks.AppIdentityProviderServiceInterface{}
	ui := &mocks.UserIdentityServiceInterface{}
	r := &mocks.InternalRegistry{}

	clientId := bson.NewObjectId().Hex()
	passSettings := &models.PasswordSettings{Min: 2, Max: 8, RequireSpecial: false, RequireUpper: false, RequireNumber: false, BcryptCost: 40}
	s.On("Set", mock.Anything, loginRememberKey, true).Return(nil)
	s.On("Get", mock.Anything, clientIdSessionKey).Return(clientId, nil)
	app.On("Get", mock.Anything).Return(&models.Application{PasswordSettings: passSettings}, nil)
	h.On("GetLoginRequest", mock.Anything).Return(&admin.GetLoginRequestOK{Payload: &models2.LoginRequest{Client: &models2.Client{ClientID: clientId}}}, nil)
	ip.On("FindByTypeAndName", mock.Anything, models.AppIdentityProviderTypePassword, models.AppIdentityProviderNameDefault).Return(&models.AppIdentityProvider{})
	ui.On("Get", mock.Anything, mock.Anything, "email").Return(nil, errors.New(""))
	r.On("ApplicationService").Return(app)
	r.On("HydraAdminApi").Return(h)

	m := &OauthManager{
		r:                       r,
		session:                 s,
		identityProviderService: ip,
		userIdentityService:     ui,
	}
	_, err := m.SignUp(getContext(), &models.Oauth2SignUpForm{Remember: true, Password: "11", Challenge: "login_challenge", Email: "email"})
	assert.NotNil(t, err)
	assert.Equal(t, "password", err.Code)
	assert.Equal(t, models.ErrorCryptPassword, err.Message)
}

func TestSignUpReturnErrorWithUnableToCreateUser(t *testing.T) {
	s := &mocks.SessionService{}
	app := &mocks.ApplicationServiceInterface{}
	h := &mocks.HydraAdminApi{}
	ip := &mocks.AppIdentityProviderServiceInterface{}
	ui := &mocks.UserIdentityServiceInterface{}
	u := &mocks.UserServiceInterface{}
	r := &mocks.InternalRegistry{}

	clientId := bson.NewObjectId().Hex()
	passSettings := &models.PasswordSettings{Min: 2, Max: 8, RequireSpecial: false, RequireUpper: false, RequireNumber: false, BcryptCost: 4}
	s.On("Set", mock.Anything, loginRememberKey, true).Return(nil)
	s.On("Get", mock.Anything, clientIdSessionKey).Return(clientId, nil)
	app.On("Get", mock.Anything).Return(&models.Application{PasswordSettings: passSettings}, nil)
	h.On("GetLoginRequest", mock.Anything).Return(&admin.GetLoginRequestOK{Payload: &models2.LoginRequest{Client: &models2.Client{ClientID: clientId}}}, nil)
	ip.On("FindByTypeAndName", mock.Anything, models.AppIdentityProviderTypePassword, models.AppIdentityProviderNameDefault).Return(&models.AppIdentityProvider{})
	ui.On("Get", mock.Anything, mock.Anything, "email").Return(nil, errors.New(""))
	u.On("Create", mock.Anything).Return(errors.New(""))
	r.On("ApplicationService").Return(app)
	r.On("HydraAdminApi").Return(h)

	m := &OauthManager{
		r:                       r,
		session:                 s,
		identityProviderService: ip,
		userIdentityService:     ui,
		userService:             u,
	}
	_, err := m.SignUp(getContext(), &models.Oauth2SignUpForm{Remember: true, Password: "11", Challenge: "login_challenge", Email: "email"})
	assert.NotNil(t, err)
	assert.Equal(t, "common", err.Code)
	assert.Equal(t, models.ErrorCreateUser, err.Message)
}

func TestSignUpReturnErrorWithUnableToCreateUserIdentity(t *testing.T) {
	s := &mocks.SessionService{}
	app := &mocks.ApplicationServiceInterface{}
	h := &mocks.HydraAdminApi{}
	ip := &mocks.AppIdentityProviderServiceInterface{}
	ui := &mocks.UserIdentityServiceInterface{}
	u := &mocks.UserServiceInterface{}
	r := &mocks.InternalRegistry{}

	clientId := bson.NewObjectId().Hex()
	passSettings := &models.PasswordSettings{Min: 2, Max: 8, RequireSpecial: false, RequireUpper: false, RequireNumber: false, BcryptCost: 4}
	s.On("Set", mock.Anything, loginRememberKey, true).Return(nil)
	s.On("Get", mock.Anything, clientIdSessionKey).Return(clientId, nil)
	app.On("Get", mock.Anything).Return(&models.Application{PasswordSettings: passSettings}, nil)
	h.On("GetLoginRequest", mock.Anything).Return(&admin.GetLoginRequestOK{Payload: &models2.LoginRequest{Client: &models2.Client{ClientID: clientId}}}, nil)
	ip.On("FindByTypeAndName", mock.Anything, models.AppIdentityProviderTypePassword, models.AppIdentityProviderNameDefault).Return(&models.AppIdentityProvider{})
	ui.On("Get", mock.Anything, mock.Anything, "email").Return(nil, errors.New(""))
	u.On("Create", mock.Anything).Return(nil)
	ui.On("Create", mock.Anything).Return(errors.New(""))
	r.On("ApplicationService").Return(app)
	r.On("HydraAdminApi").Return(h)

	m := &OauthManager{
		r:                       r,
		session:                 s,
		identityProviderService: ip,
		userIdentityService:     ui,
		userService:             u,
	}
	_, err := m.SignUp(getContext(), &models.Oauth2SignUpForm{Remember: true, Password: "11", Challenge: "login_challenge", Email: "email"})
	assert.NotNil(t, err)
	assert.Equal(t, "common", err.Code)
	assert.Equal(t, models.ErrorCreateUserIdentity, err.Message)
}

func TestSignUpReturnErrorWithUnableToAddAuthLog(t *testing.T) {
	s := &mocks.SessionService{}
	app := &mocks.ApplicationServiceInterface{}
	h := &mocks.HydraAdminApi{}
	ip := &mocks.AppIdentityProviderServiceInterface{}
	ui := &mocks.UserIdentityServiceInterface{}
	u := &mocks.UserServiceInterface{}
	a := &mocks.AuthLogServiceInterface{}
	r := &mocks.InternalRegistry{}

	clientId := bson.NewObjectId().Hex()
	passSettings := &models.PasswordSettings{Min: 2, Max: 8, RequireSpecial: false, RequireUpper: false, RequireNumber: false, BcryptCost: 4}
	s.On("Set", mock.Anything, loginRememberKey, true).Return(nil)
	s.On("Get", mock.Anything, clientIdSessionKey).Return(clientId, nil)
	app.On("Get", mock.Anything).Return(&models.Application{PasswordSettings: passSettings}, nil)
	h.On("GetLoginRequest", mock.Anything).Return(&admin.GetLoginRequestOK{Payload: &models2.LoginRequest{Client: &models2.Client{ClientID: clientId}}}, nil)
	ip.On("FindByTypeAndName", mock.Anything, models.AppIdentityProviderTypePassword, models.AppIdentityProviderNameDefault).Return(&models.AppIdentityProvider{})
	ui.On("Get", mock.Anything, mock.Anything, "email").Return(nil, errors.New(""))
	u.On("Create", mock.Anything).Return(nil)
	ui.On("Create", mock.Anything).Return(nil)
	a.On("Add", mock.Anything, mock.Anything, mock.Anything).Return(errors.New(""))
	r.On("ApplicationService").Return(app)
	r.On("HydraAdminApi").Return(h)

	m := &OauthManager{
		r:                       r,
		session:                 s,
		identityProviderService: ip,
		userIdentityService:     ui,
		userService:             u,
		authLogService:          a,
	}
	_, err := m.SignUp(getContext(), &models.Oauth2SignUpForm{Remember: true, Password: "11", Challenge: "login_challenge", Email: "email"})
	assert.NotNil(t, err)
	assert.Equal(t, "common", err.Code)
	assert.Equal(t, models.ErrorAddAuthLog, err.Message)
}

func TestSignUpReturnErrorWithUnableToAcceptLoginChallenge(t *testing.T) {
	s := &mocks.SessionService{}
	app := &mocks.ApplicationServiceInterface{}
	h := &mocks.HydraAdminApi{}
	ip := &mocks.AppIdentityProviderServiceInterface{}
	ui := &mocks.UserIdentityServiceInterface{}
	u := &mocks.UserServiceInterface{}
	a := &mocks.AuthLogServiceInterface{}
	r := &mocks.InternalRegistry{}

	clientId := bson.NewObjectId().Hex()
	passSettings := &models.PasswordSettings{Min: 2, Max: 8, RequireSpecial: false, RequireUpper: false, RequireNumber: false, BcryptCost: 4}
	s.On("Set", mock.Anything, loginRememberKey, true).Return(nil)
	s.On("Get", mock.Anything, clientIdSessionKey).Return(clientId, nil)
	app.On("Get", mock.Anything).Return(&models.Application{PasswordSettings: passSettings}, nil)
	h.On("GetLoginRequest", mock.Anything).Return(&admin.GetLoginRequestOK{Payload: &models2.LoginRequest{Client: &models2.Client{ClientID: clientId}}}, nil)
	ip.On("FindByTypeAndName", mock.Anything, models.AppIdentityProviderTypePassword, models.AppIdentityProviderNameDefault).Return(&models.AppIdentityProvider{})
	ui.On("Get", mock.Anything, mock.Anything, "email").Return(nil, errors.New(""))
	u.On("Create", mock.Anything).Return(nil)
	ui.On("Create", mock.Anything).Return(nil)
	a.On("Add", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	h.On("AcceptLoginRequest", mock.Anything).Return(nil, errors.New(""))
	r.On("ApplicationService").Return(app)
	r.On("HydraAdminApi").Return(h)

	m := &OauthManager{
		r:                       r,
		session:                 s,
		identityProviderService: ip,
		userIdentityService:     ui,
		userService:             u,
		authLogService:          a,
	}
	_, err := m.SignUp(getContext(), &models.Oauth2SignUpForm{Remember: true, Password: "11", Challenge: "login_challenge", Email: "email"})
	assert.NotNil(t, err)
	assert.Equal(t, "common", err.Code)
	assert.Equal(t, models.ErrorUnknownError, err.Message)
}

func TestSignUpReturnUrlOnSuccessResponse(t *testing.T) {
	s := &mocks.SessionService{}
	app := &mocks.ApplicationServiceInterface{}
	h := &mocks.HydraAdminApi{}
	ip := &mocks.AppIdentityProviderServiceInterface{}
	ui := &mocks.UserIdentityServiceInterface{}
	u := &mocks.UserServiceInterface{}
	a := &mocks.AuthLogServiceInterface{}
	r := &mocks.InternalRegistry{}

	clientId := bson.NewObjectId().Hex()
	passSettings := &models.PasswordSettings{Min: 2, Max: 8, RequireSpecial: false, RequireUpper: false, RequireNumber: false, BcryptCost: 4}
	s.On("Set", mock.Anything, loginRememberKey, true).Return(nil)
	s.On("Get", mock.Anything, clientIdSessionKey).Return(clientId, nil)
	app.On("Get", mock.Anything).Return(&models.Application{PasswordSettings: passSettings}, nil)
	h.On("GetLoginRequest", mock.Anything).Return(&admin.GetLoginRequestOK{Payload: &models2.LoginRequest{Client: &models2.Client{ClientID: clientId}}}, nil)
	ip.On("FindByTypeAndName", mock.Anything, models.AppIdentityProviderTypePassword, models.AppIdentityProviderNameDefault).Return(&models.AppIdentityProvider{})
	ui.On("Get", mock.Anything, mock.Anything, "email").Return(nil, errors.New(""))
	u.On("Create", mock.Anything).Return(nil)
	ui.On("Create", mock.Anything).Return(nil)
	a.On("Add", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	h.On("AcceptLoginRequest", mock.Anything).Return(&admin.AcceptLoginRequestOK{Payload: &models2.RequestHandlerResponse{RedirectTo: "url"}}, nil)
	r.On("ApplicationService").Return(app)
	r.On("HydraAdminApi").Return(h)

	m := &OauthManager{
		r:                       r,
		session:                 s,
		identityProviderService: ip,
		userIdentityService:     ui,
		userService:             u,
		authLogService:          a,
	}
	url, err := m.SignUp(getContext(), &models.Oauth2SignUpForm{Remember: true, Password: "11", Challenge: "login_challenge", Email: "email"})
	assert.Nil(t, err)
	assert.Equal(t, "url", url)
}

func TestCallBackReturnErrorWithUnableToGetClientFromSession(t *testing.T) {
	s := &mocks.SessionService{}

	s.On("Get", mock.Anything, clientIdSessionKey).Return(nil, errors.New(""))

	m := &OauthManager{session: s}
	result, err := m.CallBack(getContext(), &models.Oauth2CallBackForm{})
	assert.NotNil(t, err)
	assert.Equal(t, "client_id", err.Code)
	assert.Equal(t, "Unable to get session", err.Message)
	assert.Equal(t, false, result.Success)
	assert.Equal(t, "unknown_client_id", result.ErrorMessage)
}

func TestCallBackReturnErrorWithEmptyClientId(t *testing.T) {
	s := &mocks.SessionService{}

	s.On("Get", mock.Anything, clientIdSessionKey).Return("", nil)

	m := &OauthManager{session: s}
	result, err := m.CallBack(getContext(), &models.Oauth2CallBackForm{})
	assert.NotNil(t, err)
	assert.Equal(t, "client_id", err.Code)
	assert.Equal(t, "Unable to get client id from session", err.Message)
	assert.Equal(t, false, result.Success)
	assert.Equal(t, "unknown_client_id", result.ErrorMessage)
}

func TestCallBackReturnErrorWithUnableToGetApplication(t *testing.T) {
	s := &mocks.SessionService{}
	a := &mocks.ApplicationServiceInterface{}
	r := &mocks.InternalRegistry{}

	s.On("Get", mock.Anything, clientIdSessionKey).Return(bson.NewObjectId().Hex(), nil)
	a.On("Get", mock.Anything).Return(nil, errors.New(""))
	r.On("ApplicationService").Return(a)

	m := &OauthManager{session: s, r: r}
	result, err := m.CallBack(getContext(), &models.Oauth2CallBackForm{})
	assert.NotNil(t, err)
	assert.Equal(t, "client_id", err.Code)
	assert.Equal(t, models.ErrorClientIdIncorrect, err.Message)
	assert.Equal(t, false, result.Success)
	assert.Equal(t, "invalid_client_id", result.ErrorMessage)
}

func TestLogoutReturnErrorWithUnableToGetKeyFromSession(t *testing.T) {
	s := &mocks.SessionService{}

	s.On("Get", mock.Anything, logoutSessionKey).Return(nil, errors.New(""))

	m := &OauthManager{session: s}
	_, err := m.Logout(getContext(), &models.Oauth2LogoutForm{})
	assert.NotNil(t, err)
	assert.Equal(t, "common", err.Code)
	assert.Equal(t, models.ErrorUnknownError, err.Message)
}

func TestLogoutReturnErrorWithUnableToSetSessionAndEmptyRedirectUri(t *testing.T) {
	s := &mocks.SessionService{}

	s.On("Get", mock.Anything, logoutSessionKey).Return("", nil)
	s.On("Set", mock.Anything, logoutSessionKey, "auth1").Return(errors.New(""))

	m := &OauthManager{session: s}
	_, err := m.Logout(getContext(), &models.Oauth2LogoutForm{})
	assert.NotNil(t, err)
	assert.Equal(t, "common", err.Code)
	assert.Equal(t, models.ErrorUnknownError, err.Message)
}

func TestLogoutReturnRevokeHydraUrl(t *testing.T) {
	s := &mocks.SessionService{}

	s.On("Get", mock.Anything, logoutSessionKey).Return("", nil)
	s.On("Set", mock.Anything, logoutSessionKey, "auth1").Return(nil)

	m := &OauthManager{session: s}
	url, err := m.Logout(getContext(), &models.Oauth2LogoutForm{})
	assert.Nil(t, err)
	assert.Equal(t, logoutHydraUrl, url)
}

func TestLogoutReturnErrorWithUnableToSetEmptyUrl(t *testing.T) {
	s := &mocks.SessionService{}

	s.On("Get", mock.Anything, logoutSessionKey).Return("url", nil)
	s.On("Set", mock.Anything, logoutSessionKey, "").Return(errors.New(""))

	m := &OauthManager{session: s}
	_, err := m.Logout(getContext(), &models.Oauth2LogoutForm{})
	assert.NotNil(t, err)
	assert.Equal(t, "common", err.Code)
	assert.Equal(t, models.ErrorUnknownError, err.Message)
}

func TestLogoutReturnCustomUrl(t *testing.T) {
	s := &mocks.SessionService{}

	s.On("Get", mock.Anything, logoutSessionKey).Return("url", nil)
	s.On("Set", mock.Anything, logoutSessionKey, "").Return(nil)

	m := &OauthManager{session: s}
	url, err := m.Logout(getContext(), &models.Oauth2LogoutForm{})
	assert.Nil(t, err)
	assert.Equal(t, "url", url)
}

func TestLogoutReturnEmptyUrl(t *testing.T) {
	s := &mocks.SessionService{}

	s.On("Get", mock.Anything, logoutSessionKey).Return("auth1", nil)
	s.On("Set", mock.Anything, logoutSessionKey, "").Return(nil)

	m := &OauthManager{session: s}
	url, err := m.Logout(getContext(), &models.Oauth2LogoutForm{})
	assert.Nil(t, err)
	assert.Equal(t, "", url)
}

func TestLoadRemoteScopesReturnNil(t *testing.T) {
	m := &OauthManager{}
	err := m.loadRemoteScopes([]string{"scope1"})
	assert.Nil(t, err)
}
