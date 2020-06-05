package manager

import (
	"testing"

	"github.com/ProtocolONE/auth1.protocol.one/internal/domain/entity"
	"github.com/ProtocolONE/auth1.protocol.one/internal/domain/repository"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/mocks"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/models"
	"github.com/globalsign/mgo/bson"
	"github.com/ory/hydra-client-go/client/admin"
	models2 "github.com/ory/hydra-client-go/models"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type testOAuth2 struct {
	app  *mocks.ApplicationServiceInterface
	h    *mocks.HydraAdminApi
	ip   *mocks.AppIdentityProviderServiceInterface
	sess *mocks.SessionService
	uis  *mocks.UserIdentityServiceInterface
	us   *mocks.UserServiceInterface
	ott  *mocks.OneTimeTokenServiceInterface
	al   *mocks.AuthLogServiceInterface

	r *mocks.InternalRegistry
	m *OauthManager

	space        *entity.Space
	loginRequest *admin.GetLoginRequestOK
}

func newTestOAuth2() *testOAuth2 {
	return &testOAuth2{
		app:  &mocks.ApplicationServiceInterface{},
		h:    &mocks.HydraAdminApi{},
		ip:   &mocks.AppIdentityProviderServiceInterface{},
		sess: &mocks.SessionService{},
		uis:  &mocks.UserIdentityServiceInterface{},
		us:   &mocks.UserServiceInterface{},
		ott:  &mocks.OneTimeTokenServiceInterface{},
		al:   &mocks.AuthLogServiceInterface{},
		r:    mockIntRegistry(),

		space: &entity.Space{PasswordSettings: entity.PasswordSettings{Min: 1, Max: 8, BcryptCost: 4}},
		loginRequest: &admin.GetLoginRequestOK{Payload: &models2.LoginRequest{
			Client:  &models2.OAuth2Client{ClientID: bson.NewObjectId().Hex()},
			Subject: "subj",
		}},
	}
}

func (test *testOAuth2) init() {
	test.app.On("Get", mock.Anything).Return(&models.Application{}, nil)

	test.h.On("GetLoginRequest", mock.Anything).Return(test.loginRequest, nil)
	test.h.On("AcceptLoginRequest", mock.Anything).Return(&admin.AcceptLoginRequestOK{Payload: &models2.CompletedRequest{RedirectTo: "url"}}, nil)

	test.ip.On("FindByType", mock.Anything, models.AppIdentityProviderTypeSocial).Return([]*models.AppIdentityProvider{{}})
	test.ip.On("FindByTypeAndName", mock.Anything, models.AppIdentityProviderTypePassword, models.AppIdentityProviderNameDefault).Return(&models.AppIdentityProvider{})

	test.sess.On("Set", mock.Anything, clientIdSessionKey, mock.Anything).Return(nil)
	test.sess.On("Set", mock.Anything, loginRememberKey, mock.Anything).Return(nil)

	test.uis.On("Get", mock.Anything, "email").Return(nil, errors.New(""))
	// be := models.NewBcryptEncryptor(&models.CryptConfig{Cost: test.space.PasswordSettings.BcryptCost})
	// passHash, _ := be.Digest("1234")
	// test.uis.On("Get", mock.Anything, "email").Return(&models.UserIdentity{Credential: passHash}, nil)
	test.uis.On("Create", mock.Anything).Return(nil)

	test.us.On("Create", mock.Anything).Return(nil)
	test.us.On("Get", mock.Anything).Return(&models.User{}, nil)
	test.us.On("Update", mock.Anything).Return(nil)

	test.ott.On("Use", "invalid_auth_token", mock.Anything).Return(nil)

	test.al.On("Add", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)

	test.r.On("OneTimeTokenService").Return(test.ott)
	test.r.On("HydraAdminApi").Return(test.h)
	test.r.On("ApplicationService").Return(test.app)
	test.r.On("Spaces").Return(repository.OneSpaceRepo(test.space))

	test.m = &OauthManager{
		r:                       test.r,
		identityProviderService: test.ip,
		session:                 test.sess,
		userService:             test.us,
		userIdentityService:     test.uis,
		authLogService:          test.al,
	}
}

func TestSignUpReturnUrlOnSuccessResponse(t *testing.T) {
	test := newTestOAuth2()
	test.init()

	url, err := test.m.SignUp(getContext(), &models.Oauth2SignUpForm{Remember: true, Password: "11", Challenge: "login_challenge", Email: "email"})
	assert.Nil(t, err)
	assert.Equal(t, "url", url)
}

func TestCheckAuthReturnEmptyWithoutSkip(t *testing.T) {
	test := newTestOAuth2()
	test.init()

	url, err := test.m.CheckAuth(getContext(), &models.Oauth2LoginForm{Challenge: "login_challenge"})
	assert.Nil(t, err)
	assert.Equal(t, "", url)
}

func TestCheckAuthReturnSuccessWithEmptySubject(t *testing.T) {
	test := newTestOAuth2()
	clientId := bson.NewObjectId().Hex()
	test.h.On("GetLoginRequest", mock.Anything).Return(&admin.GetLoginRequestOK{Payload: &models2.LoginRequest{Client: &models2.OAuth2Client{ClientID: clientId}}}, nil)
	test.init()

	url, err := test.m.CheckAuth(getContext(), &models.Oauth2LoginForm{Challenge: "login_challenge"})
	assert.Nil(t, err)
	assert.Equal(t, "", url)
}

func TestCheckAuthReturnUrlForSkipStep(t *testing.T) {
	test := newTestOAuth2()
	clientId := bson.NewObjectId().Hex()
	test.h.On("GetLoginRequest", mock.Anything).Return(&admin.GetLoginRequestOK{Payload: &models2.LoginRequest{Client: &models2.OAuth2Client{ClientID: clientId}, Subject: bson.NewObjectId().Hex(), Skip: true}}, nil)
	test.h.On("AcceptLoginRequest", mock.Anything).Return(&admin.AcceptLoginRequestOK{Payload: &models2.CompletedRequest{RedirectTo: "url"}}, nil)
	test.init()

	url, err := test.m.CheckAuth(getContext(), &models.Oauth2LoginForm{Challenge: "login_challenge"})
	assert.Nil(t, err)
	assert.Equal(t, "url", url)
}

func TestAuthReturnUrlToConsentRequest(t *testing.T) {
	test := newTestOAuth2()
	test.init()

	url, err := test.m.Auth(getContext(), &models.Oauth2LoginSubmitForm{Challenge: "login_challenge", Remember: true, PreviousLogin: "subj"})
	assert.Nil(t, err)
	assert.Equal(t, "url", url)
}

///////////////////////////////////////////////////////////////////////
// Negative cases

func TestCheckAuthReturnErrorWithUnableToGetLoginRequest(t *testing.T) {
	test := newTestOAuth2()
	test.h.On("GetLoginRequest", mock.Anything).Return(nil, errors.New(""))
	test.init()

	_, err := test.m.CheckAuth(getContext(), &models.Oauth2LoginForm{Challenge: "login_challenge"})
	if assert.NotNil(t, err) {
		assert.Equal(t, "common", err.Code)
		assert.Equal(t, models.ErrorLoginChallenge, err.Message)
	}
}

func TestCheckAuthReturnErrorWithUnableToSetClientIdToSession(t *testing.T) {
	test := newTestOAuth2()
	test.sess.On("Set", mock.Anything, clientIdSessionKey, mock.Anything).Return(errors.New(""))
	test.init()

	_, err := test.m.CheckAuth(getContext(), &models.Oauth2LoginForm{Challenge: "login_challenge"})
	if assert.NotNil(t, err) {
		assert.Equal(t, "common", err.Code)
		assert.Equal(t, models.ErrorUnknownError, err.Message)
	}
}

func TestCheckAuthReturnErrorWithUnableToSetRememberToSession(t *testing.T) {
	test := newTestOAuth2()
	test.sess.On("Set", mock.Anything, loginRememberKey, mock.Anything).Return(errors.New(""))
	test.init()

	_, err := test.m.CheckAuth(getContext(), &models.Oauth2LoginForm{Challenge: "login_challenge"})
	if assert.NotNil(t, err) {
		assert.Equal(t, "common", err.Code)
		assert.Equal(t, models.ErrorUnknownError, err.Message)
	}
}

func TestCheckAuthReturnErrorWithUnableToAcceptLoginRequest(t *testing.T) {
	test := newTestOAuth2()
	clientId := bson.NewObjectId().Hex()
	test.h.On("GetLoginRequest", mock.Anything).Return(&admin.GetLoginRequestOK{Payload: &models2.LoginRequest{Client: &models2.OAuth2Client{ClientID: clientId}, Subject: bson.NewObjectId().Hex(), Skip: true}}, nil)
	test.h.On("AcceptLoginRequest", mock.Anything).Return(nil, errors.New(""))
	test.init()

	url, err := test.m.CheckAuth(getContext(), &models.Oauth2LoginForm{Challenge: "login_challenge"})
	if assert.NotNil(t, err) {
		assert.Equal(t, "common", err.Code)
		assert.Equal(t, models.ErrorUnknownError, err.Message)
	}
	assert.Equal(t, "", url)
}

func TestAuthReturnErrorWithUnableToGetLoginRequest(t *testing.T) {
	test := newTestOAuth2()
	test.h.On("GetLoginRequest", mock.Anything).Return(nil, errors.New(""))
	test.init()

	_, err := test.m.Auth(getContext(), &models.Oauth2LoginSubmitForm{Challenge: "login_challenge"})
	assert.NotNil(t, err)
	// assert.Equal(t, "common", err.Code)
	// assert.Equal(t, models.ErrorLoginChallenge, err.Message)
}

func TestAuthReturnErrorWithIncorrectToken(t *testing.T) {
	test := newTestOAuth2()
	test.loginRequest.Payload.Subject = ""
	test.ott.On("Use", "invalid_auth_token", mock.Anything).Return(errors.New(""))
	test.init()

	_, err := test.m.Auth(getContext(), &models.Oauth2LoginSubmitForm{Challenge: "login_challenge", Token: "invalid_auth_token"})
	assert.NotNil(t, err)
	// assert.Equal(t, "common", err.Code)
	// assert.Equal(t, models.ErrorCannotUseToken, err.Message)
}

func TestAuthReturnErrorWithIncorrectClient(t *testing.T) {
	test := newTestOAuth2()
	test.app.On("Get", mock.Anything).Return(nil, errors.New(""))
	test.init()

	_, err := test.m.Auth(getContext(), &models.Oauth2LoginSubmitForm{Challenge: "login_challenge"})
	assert.NotNil(t, err)
	// assert.Equal(t, "client_id", err.Code)
	// assert.Equal(t, models.ErrorClientIdIncorrect, err.Message)
}

func TestAuthReturnErrorWithUnavailableIdentityProvider(t *testing.T) {
	test := newTestOAuth2()
	test.ip.On("FindByTypeAndName", mock.Anything, models.AppIdentityProviderTypePassword, models.AppIdentityProviderNameDefault).Return(nil)
	test.init()

	_, err := test.m.Auth(getContext(), &models.Oauth2LoginSubmitForm{Challenge: "login_challenge"})
	assert.NotNil(t, err)
	// assert.Equal(t, "client_id", err.Code)
	// assert.Equal(t, models.ErrorClientIdIncorrect, err.Message)
}

func TestAuthReturnErrorWithUnavailableUserIdentity(t *testing.T) {
	test := newTestOAuth2()
	test.uis.On("Get", mock.Anything, "invalid_email").Return(nil, errors.New(""))
	test.init()

	_, err := test.m.Auth(getContext(), &models.Oauth2LoginSubmitForm{Challenge: "login_challenge", Email: "invalid_email"})
	assert.NotNil(t, err)
	// assert.Equal(t, "email", err.Code)
	// assert.Equal(t, models.ErrorLoginIncorrect, err.Message)
}

func TestAuthReturnErrorWithComparePassword(t *testing.T) {
	test := newTestOAuth2()
	test.uis.On("Get", mock.Anything, "email").Return(&models.UserIdentity{Credential: "1"}, nil)
	test.init()

	_, err := test.m.Auth(getContext(), &models.Oauth2LoginSubmitForm{Challenge: "login_challenge", Email: "email", Password: "1234"})
	assert.NotNil(t, err)
	// assert.Equal(t, "password", err.Code)
	// assert.Equal(t, models.ErrorPasswordIncorrect, err.Message)
}

func TestAuthReturnErrorWithUnableToGetUser(t *testing.T) {
	test := newTestOAuth2()
	test.us.On("Get", mock.Anything).Return(nil, errors.New(""))
	test.init()

	_, err := test.m.Auth(getContext(), &models.Oauth2LoginSubmitForm{Challenge: "login_challenge", Email: "email", Password: "1234"})
	assert.NotNil(t, err)
	// assert.Equal(t, "email", err.Code)
	// assert.Equal(t, models.ErrorLoginIncorrect, err.Message)
}

func TestAuthReturnErrorWithUnableToUpdateUser(t *testing.T) {
	test := newTestOAuth2()
	test.us.On("Update", mock.Anything).Return(errors.New(""))
	test.init()

	_, err := test.m.Auth(getContext(), &models.Oauth2LoginSubmitForm{Challenge: "login_challenge", Email: "email", Password: "1234"})
	assert.NotNil(t, err)
	// assert.Equal(t, "common", err.Code)
	// assert.Equal(t, models.ErrorUpdateUser, err.Message)
}

func TestAuthReturnErrorWithUnableToAddAuthLog(t *testing.T) {
	test := newTestOAuth2()
	test.al.On("Add", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(errors.New(""))
	test.init()

	_, err := test.m.Auth(getContext(), &models.Oauth2LoginSubmitForm{Challenge: "login_challenge", Email: "email", Password: "1234"})
	assert.NotNil(t, err)
	// assert.Equal(t, "common", err.Code)
	// assert.Equal(t, models.ErrorAddAuthLog, err.Message)
}

func TestAuthReturnErrorWithUnableToSetSessionRemember(t *testing.T) {
	test := newTestOAuth2()
	test.sess.On("Set", mock.Anything, loginRememberKey, true).Return(errors.New(""))
	test.init()

	_, err := test.m.Auth(getContext(), &models.Oauth2LoginSubmitForm{Challenge: "login_challenge", Remember: true, PreviousLogin: "subj"})
	assert.NotNil(t, err)
	// assert.Equal(t, "common", err.Code)
	// assert.Equal(t, models.ErrorUnknownError, err.Message)
}

func TestAuthReturnErrorWithUnableToAcceptLoginRequest(t *testing.T) {
	test := newTestOAuth2()
	test.h.On("AcceptLoginRequest", mock.Anything).Return(nil, errors.New(""))
	test.init()

	_, err := test.m.Auth(getContext(), &models.Oauth2LoginSubmitForm{Challenge: "login_challenge", Remember: true, PreviousLogin: "subj"})
	assert.NotNil(t, err)
	// assert.Equal(t, "common", err.Code)
	// assert.Equal(t, models.ErrorPasswordIncorrect, err.Message)
}

func TestGetScopes(t *testing.T) {
	m := &OauthManager{}
	scopes := []string{"openid", "offline"}
	assert.Equal(t, scopes, m.GetScopes(append(scopes, "offline")))
}

func TestConsentReturnErrorWithUnableToGetConsentRequest(t *testing.T) {
	h := &mocks.HydraAdminApi{}
	r := mockIntRegistry()

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
	r := mockIntRegistry()

	h.On("GetConsentRequest", mock.Anything).Return(&admin.GetConsentRequestOK{Payload: &models2.ConsentRequest{Client: &models2.OAuth2Client{ClientID: bson.NewObjectId().Hex()}}}, nil)
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
	r := mockIntRegistry()

	h.On("GetConsentRequest", mock.Anything).Return(&admin.GetConsentRequestOK{Payload: &models2.ConsentRequest{Client: &models2.OAuth2Client{ClientID: bson.NewObjectId().Hex()}, RequestedScope: []string{"openid", "offline"}}}, nil)
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
	r := mockIntRegistry()

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
	r := mockIntRegistry()

	h.On("GetConsentRequest", mock.Anything).Return(&admin.GetConsentRequestOK{Payload: &models2.ConsentRequest{Client: &models2.OAuth2Client{ClientID: bson.NewObjectId().Hex()}, Subject: bson.NewObjectId().Hex()}}, nil)
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
	r := mockIntRegistry()

	h.On("GetConsentRequest", mock.Anything).Return(&admin.GetConsentRequestOK{Payload: &models2.ConsentRequest{Client: &models2.OAuth2Client{ClientID: bson.NewObjectId().Hex()}, Subject: bson.NewObjectId().Hex(), Skip: true}}, nil)
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
	r := mockIntRegistry()

	h.On("GetConsentRequest", mock.Anything).Return(&admin.GetConsentRequestOK{Payload: &models2.ConsentRequest{Client: &models2.OAuth2Client{ClientID: bson.NewObjectId().Hex()}, Subject: bson.NewObjectId().Hex()}}, nil)
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
	r := mockIntRegistry()

	h.On("GetConsentRequest", mock.Anything).Return(&admin.GetConsentRequestOK{Payload: &models2.ConsentRequest{Client: &models2.OAuth2Client{ClientID: bson.NewObjectId().Hex()}, Subject: bson.NewObjectId().Hex()}}, nil)
	s.On("Set", mock.Anything, clientIdSessionKey, mock.Anything).Return(nil)
	us.On("Get", mock.Anything).Return(&models.User{}, nil)
	h.On("AcceptConsentRequest", mock.Anything).Return(&admin.AcceptConsentRequestOK{Payload: &models2.CompletedRequest{RedirectTo: "url"}}, nil)
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
	r := mockIntRegistry()

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
	r := mockIntRegistry()

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
	r := mockIntRegistry()

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
	r := mockIntRegistry()

	app.On("Get", mock.Anything).Return(&models.Application{AuthSecret: "1"}, nil)
	h.On("IntrospectOAuth2Token", mock.Anything, mock.Anything).Return(&admin.IntrospectOAuth2TokenOK{Payload: &models2.OAuth2TokenIntrospection{}}, nil)
	r.On("ApplicationService").Return(app)
	r.On("HydraAdminApi").Return(h)

	m := &OauthManager{r: r}
	result, err := m.Introspect(getContext(), &models.Oauth2IntrospectForm{ClientID: bson.NewObjectId().Hex(), Secret: "1"})
	assert.Nil(t, err)
	assert.Equal(t, &models.Oauth2TokenIntrospection{}, result)
}

func TestSignUpReturnErrorWithUnableToSetRememberToSession(t *testing.T) {
	test := newTestOAuth2()
	test.sess.On("Set", mock.Anything, loginRememberKey, true).Return(errors.New(""))
	test.init()

	_, err := test.m.SignUp(getContext(), &models.Oauth2SignUpForm{Remember: true})
	assert.NotNil(t, err)
	// assert.Equal(t, "common", err.Code)
	// assert.Equal(t, models.ErrorUnknownError, err.Message)
}

func TestSignUpReturnErrorWithInvalidPassword(t *testing.T) {
	test := newTestOAuth2()
	test.space.PasswordSettings.Min = 2
	test.init()

	_, err := test.m.SignUp(getContext(), &models.Oauth2SignUpForm{Remember: true, Password: "1"})
	assert.NotNil(t, err)
	// assert.Equal(t, "password", err.Code)
	// assert.Equal(t, models.ErrorPasswordIncorrect, err.Message)
}

func TestSignUpReturnErrorWithUnableToGetLoginChallenge(t *testing.T) {
	test := newTestOAuth2()
	test.h.On("GetLoginRequest", mock.Anything).Return(nil, errors.New(""))
	test.init()

	_, err := test.m.SignUp(getContext(), &models.Oauth2SignUpForm{Remember: true, Password: "11", Challenge: "login_challenge"})
	assert.NotNil(t, err)
	// assert.Equal(t, "common", err.Code)
	// assert.Equal(t, models.ErrorLoginChallenge, err.Message)
}

func TestSignUpReturnErrorWithUnavailableIdentityProvider(t *testing.T) {
	test := newTestOAuth2()
	test.ip.On("FindByTypeAndName", mock.Anything, models.AppIdentityProviderTypePassword, models.AppIdentityProviderNameDefault).Return(nil)
	test.init()

	_, err := test.m.SignUp(getContext(), &models.Oauth2SignUpForm{Remember: true, Password: "11", Challenge: "login_challenge"})
	assert.NotNil(t, err)
	// assert.Equal(t, "client_id", err.Code)
	// assert.Equal(t, models.ErrorProviderIdIncorrect, err.Message)
}

func TestSignUpReturnErrorWithUnableToGetUserIdentity(t *testing.T) {
	test := newTestOAuth2()
	test.uis.On("Get", mock.Anything, "email").Return(&models.UserIdentity{}, nil)
	test.init()

	_, err := test.m.SignUp(getContext(), &models.Oauth2SignUpForm{Remember: true, Password: "11", Challenge: "login_challenge", Email: "email"})
	assert.NotNil(t, err)
	// assert.Equal(t, "email", err.Code)
	// assert.Equal(t, models.ErrorLoginIncorrect, err.Message)
}

func TestSignUpReturnErrorWithEncryptPassword(t *testing.T) {
	test := newTestOAuth2()
	test.space.PasswordSettings.BcryptCost = 40
	test.init()

	_, err := test.m.SignUp(getContext(), &models.Oauth2SignUpForm{Remember: true, Password: "11", Challenge: "login_challenge", Email: "email"})
	assert.NotNil(t, err)
	// assert.Equal(t, "password", err.Code)
	// assert.Equal(t, models.ErrorCryptPassword, err.Message)
}

func TestSignUpReturnErrorWithUnableToCreateUser(t *testing.T) {
	test := newTestOAuth2()
	test.us.On("Create", mock.Anything).Return(errors.New(""))
	test.init()

	_, err := test.m.SignUp(getContext(), &models.Oauth2SignUpForm{Remember: true, Password: "11", Challenge: "login_challenge", Email: "email"})
	assert.NotNil(t, err)
	// assert.Equal(t, "common", err.Code)
	// assert.Equal(t, models.ErrorCreateUser, err.Message)
}

func TestSignUpReturnErrorWithUnableToCreateUserIdentity(t *testing.T) {
	test := newTestOAuth2()
	test.uis.On("Create", mock.Anything).Return(errors.New(""))
	test.init()

	_, err := test.m.SignUp(getContext(), &models.Oauth2SignUpForm{Remember: true, Password: "11", Challenge: "login_challenge", Email: "email"})
	assert.NotNil(t, err)
	// assert.Equal(t, "common", err.Code)
	// assert.Equal(t, models.ErrorCreateUserIdentity, err.Message)
}

func TestSignUpReturnErrorWithUnableToAddAuthLog(t *testing.T) {
	test := newTestOAuth2()
	test.al.On("Add", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(errors.New(""))
	test.init()

	_, err := test.m.SignUp(getContext(), &models.Oauth2SignUpForm{Remember: true, Password: "11", Challenge: "login_challenge", Email: "email"})
	assert.NotNil(t, err)
	// assert.Equal(t, "common", err.Code)
	// assert.Equal(t, models.ErrorAddAuthLog, err.Message)
}

func TestSignUpReturnErrorWithUnableToAcceptLoginChallenge(t *testing.T) {
	test := newTestOAuth2()
	test.h.On("AcceptLoginRequest", mock.Anything).Return(nil, errors.New(""))
	test.init()

	_, err := test.m.SignUp(getContext(), &models.Oauth2SignUpForm{Remember: true, Password: "11", Challenge: "login_challenge", Email: "email"})
	assert.NotNil(t, err)
	// assert.Equal(t, "common", err.Code)
	// assert.Equal(t, models.ErrorUnknownError, err.Message)
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
	r := mockIntRegistry()

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

func TestHasOnlyDefaultScopes(t *testing.T) {
	assert.True(t, hasOnlyDefaultScopes([]string{}))
	assert.True(t, hasOnlyDefaultScopes([]string{scopeOpenId})) // fail
	assert.True(t, hasOnlyDefaultScopes([]string{scopeOffline}))
	assert.True(t, hasOnlyDefaultScopes([]string{scopeOpenId, scopeOffline}))
	assert.True(t, hasOnlyDefaultScopes([]string{scopeOffline, scopeOpenId}))
	assert.False(t, hasOnlyDefaultScopes([]string{"other"}))
	assert.False(t, hasOnlyDefaultScopes([]string{scopeOpenId, "other"}))  // fail
	assert.False(t, hasOnlyDefaultScopes([]string{"other", scopeOffline})) // fail
	assert.False(t, hasOnlyDefaultScopes([]string{scopeOpenId, scopeOffline, "other"}))
	assert.False(t, hasOnlyDefaultScopes([]string{scopeOffline, "other", scopeOpenId}))
}
