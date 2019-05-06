package manager

import (
	"encoding/base64"
	"encoding/json"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/mocks"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/models"
	"github.com/globalsign/mgo/bson"
	"github.com/labstack/echo/v4"
	"github.com/ory/hydra/sdk/go/hydra/client/admin"
	models2 "github.com/ory/hydra/sdk/go/hydra/models"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAuthorizeReturnErrorWithIncorrectClient(t *testing.T) {
	app := &mocks.ApplicationServiceInterface{}
	r := &mocks.InternalRegistry{}

	app.On("Get", mock.Anything).Return(nil, errors.New(""))
	r.On("ApplicationService").Return(app)

	m := &LoginManager{r: r}
	_, err := m.Authorize(getContext(), &models.AuthorizeForm{ClientID: bson.NewObjectId().Hex()})
	assert.NotNil(t, err)
	assert.Equal(t, "client_id", err.Code)
	assert.Equal(t, models.ErrorClientIdIncorrect, err.Message)
}

func TestAuthorizeReturnErrorWithUnavailableIdentityProvider(t *testing.T) {
	ip := &mocks.AppIdentityProviderServiceInterface{}
	app := &mocks.ApplicationServiceInterface{}
	r := &mocks.InternalRegistry{}

	app.On("Get", mock.Anything).Return(&models.Application{}, nil)
	ip.On("FindByTypeAndName", mock.Anything, models.AppIdentityProviderTypeSocial, mock.Anything).Return(nil)
	r.On("ApplicationService").Return(app)

	m := &LoginManager{
		r:                       r,
		identityProviderService: ip,
	}
	_, err := m.Authorize(getContext(), &models.AuthorizeForm{ClientID: bson.NewObjectId().Hex()})
	assert.NotNil(t, err)
	assert.Equal(t, "client_id", err.Code)
	assert.Equal(t, models.ErrorClientIdIncorrect, err.Message)
}

func TestAuthorizeReturnErrorWithUnavailableToGetAuthUrl(t *testing.T) {
	ip := &mocks.AppIdentityProviderServiceInterface{}
	app := &mocks.ApplicationServiceInterface{}
	r := &mocks.InternalRegistry{}

	app.On("Get", mock.Anything).Return(&models.Application{}, nil)
	ip.On("FindByTypeAndName", mock.Anything, models.AppIdentityProviderTypeSocial, mock.Anything).Return(&models.AppIdentityProvider{})
	ip.On("GetAuthUrl", mock.Anything, mock.Anything, mock.Anything).Return("", errors.New(""))
	r.On("ApplicationService").Return(app)

	m := &LoginManager{
		r:                       r,
		identityProviderService: ip,
	}
	_, err := m.Authorize(getContext(), &models.AuthorizeForm{ClientID: bson.NewObjectId().Hex()})
	assert.NotNil(t, err)
	assert.Equal(t, "common", err.Code)
	assert.Equal(t, models.ErrorUnknownError, err.Message)
}

func TestAuthorizeReturnUrlOnSuccessResult(t *testing.T) {
	ip := &mocks.AppIdentityProviderServiceInterface{}
	app := &mocks.ApplicationServiceInterface{}
	r := &mocks.InternalRegistry{}

	app.On("Get", mock.Anything).Return(&models.Application{}, nil)
	ip.On("FindByTypeAndName", mock.Anything, models.AppIdentityProviderTypeSocial, mock.Anything).Return(&models.AppIdentityProvider{})
	ip.On("GetAuthUrl", mock.Anything, mock.Anything, mock.Anything).Return("url", nil)
	r.On("ApplicationService").Return(app)

	m := &LoginManager{
		r:                       r,
		identityProviderService: ip,
	}
	url, err := m.Authorize(getContext(), &models.AuthorizeForm{ClientID: bson.NewObjectId().Hex()})
	assert.Nil(t, err)
	assert.Equal(t, "url", url)
}

func TestAuthorizeResultReturnErrorWithInvalidState(t *testing.T) {
	r := &mocks.InternalRegistry{}

	m := &LoginManager{r: r}
	_, err := m.AuthorizeResult(getContext(), &models.AuthorizeResultForm{State: ""})
	assert.NotNil(t, err)
	assert.Equal(t, "common", err.Code)
	assert.Equal(t, models.ErrorUnknownError, err.Message)
}

func TestAuthorizeResultReturnErrorWithUnableDecodeForm(t *testing.T) {
	r := &mocks.InternalRegistry{}

	m := &LoginManager{r: r}
	_, err := m.AuthorizeResult(getContext(), &models.AuthorizeResultForm{State: "1"})
	assert.NotNil(t, err)
	assert.Equal(t, "common", err.Code)
	assert.Equal(t, models.ErrorUnknownError, err.Message)
}

func TestAuthorizeResultReturnErrorWithUnableRestoreAuthForm(t *testing.T) {
	r := &mocks.InternalRegistry{}

	m := &LoginManager{r: r}
	_, err := m.AuthorizeResult(getContext(), &models.AuthorizeResultForm{State: "dGVzdA=="})
	assert.NotNil(t, err)
	assert.Equal(t, "common", err.Code)
	assert.Equal(t, models.ErrorUnknownError, err.Message)
}

func TestAuthorizeResultReturnErrorWithIncorrectClient(t *testing.T) {
	app := &mocks.ApplicationServiceInterface{}
	r := &mocks.InternalRegistry{}

	app.On("Get", mock.Anything).Return(nil, errors.New(""))
	r.On("ApplicationService").Return(app)

	m := &LoginManager{r: r}
	form, _ := json.Marshal(&models.AuthorizeForm{ClientID: bson.NewObjectId().Hex()})
	_, err := m.AuthorizeResult(getContext(), &models.AuthorizeResultForm{State: base64.StdEncoding.EncodeToString(form)})
	assert.NotNil(t, err)
	assert.Equal(t, "client_id", err.Code)
	assert.Equal(t, models.ErrorClientIdIncorrect, err.Message)
}

func TestAuthorizeResultReturnErrorWithUnavailableIdentityProvider(t *testing.T) {
	ip := &mocks.AppIdentityProviderServiceInterface{}
	app := &mocks.ApplicationServiceInterface{}
	r := &mocks.InternalRegistry{}

	app.On("Get", mock.Anything).Return(&models.Application{}, nil)
	ip.On("FindByTypeAndName", mock.Anything, models.AppIdentityProviderTypeSocial, mock.Anything).Return(nil)
	r.On("ApplicationService").Return(app)

	m := &LoginManager{
		r:                       r,
		identityProviderService: ip,
	}
	form, _ := json.Marshal(&models.AuthorizeForm{ClientID: bson.NewObjectId().Hex()})
	_, err := m.AuthorizeResult(getContext(), &models.AuthorizeResultForm{State: base64.StdEncoding.EncodeToString(form)})
	assert.NotNil(t, err)
	assert.Equal(t, "common", err.Code)
	assert.Equal(t, models.ErrorConnectionIncorrect, err.Message)
}

func TestAuthorizeResultReturnErrorWithUnableToGetSocialProfile(t *testing.T) {
	ip := &mocks.AppIdentityProviderServiceInterface{}
	app := &mocks.ApplicationServiceInterface{}
	r := &mocks.InternalRegistry{}

	app.On("Get", mock.Anything).Return(&models.Application{}, nil)
	ip.On("FindByTypeAndName", mock.Anything, models.AppIdentityProviderTypeSocial, mock.Anything).Return(&models.AppIdentityProvider{})
	ip.On("GetSocialProfile", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil, errors.New(""))
	r.On("ApplicationService").Return(app)

	m := &LoginManager{
		r:                       r,
		identityProviderService: ip,
	}
	form, _ := json.Marshal(&models.AuthorizeForm{ClientID: bson.NewObjectId().Hex()})
	_, err := m.AuthorizeResult(getContext(), &models.AuthorizeResultForm{State: base64.StdEncoding.EncodeToString(form)})
	assert.NotNil(t, err)
	assert.Equal(t, "common", err.Code)
	assert.Equal(t, models.ErrorGetSocialData, err.Message)
}

func TestAuthorizeResultReturnErrorWithUnableToGetExistedUserByExistedUserIdentity(t *testing.T) {
	ip := &mocks.AppIdentityProviderServiceInterface{}
	ui := &mocks.UserIdentityServiceInterface{}
	us := &mocks.UserServiceInterface{}
	app := &mocks.ApplicationServiceInterface{}
	r := &mocks.InternalRegistry{}

	app.On("Get", mock.Anything).Return(&models.Application{}, nil)
	ip.On("FindByTypeAndName", mock.Anything, models.AppIdentityProviderTypeSocial, mock.Anything).Return(&models.AppIdentityProvider{})
	ip.On("GetSocialProfile", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(&models.UserIdentitySocial{ID: "1"}, nil)
	ui.On("Get", mock.Anything, mock.Anything, mock.Anything).Return(&models.UserIdentity{}, nil)
	us.On("Get", mock.Anything).Return(nil, errors.New(""))
	r.On("ApplicationService").Return(app)

	m := &LoginManager{
		r:                       r,
		identityProviderService: ip,
		userIdentityService:     ui,
		userService:             us,
	}
	form, _ := json.Marshal(&models.AuthorizeForm{ClientID: bson.NewObjectId().Hex()})
	_, err := m.AuthorizeResult(getContext(), &models.AuthorizeResultForm{State: base64.StdEncoding.EncodeToString(form)})
	assert.NotNil(t, err)
	assert.Equal(t, "common", err.Code)
	assert.Equal(t, models.ErrorLoginIncorrect, err.Message)
}

func TestAuthorizeResultReturnErrorWithAddAuthLogByExistedUserIdentity(t *testing.T) {
	ip := &mocks.AppIdentityProviderServiceInterface{}
	ui := &mocks.UserIdentityServiceInterface{}
	us := &mocks.UserServiceInterface{}
	as := &mocks.AuthLogServiceInterface{}
	app := &mocks.ApplicationServiceInterface{}
	r := &mocks.InternalRegistry{}

	app.On("Get", mock.Anything).Return(&models.Application{}, nil)
	ip.On("FindByTypeAndName", mock.Anything, models.AppIdentityProviderTypeSocial, mock.Anything).Return(&models.AppIdentityProvider{})
	ip.On("GetSocialProfile", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(&models.UserIdentitySocial{ID: "1"}, nil)
	ui.On("Get", mock.Anything, mock.Anything, mock.Anything).Return(&models.UserIdentity{}, nil)
	us.On("Get", mock.Anything).Return(&models.User{}, nil)
	as.On("Add", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(errors.New(""))
	r.On("ApplicationService").Return(app)

	m := &LoginManager{
		r:                       r,
		identityProviderService: ip,
		userIdentityService:     ui,
		userService:             us,
		authLogService:          as,
	}
	form, _ := json.Marshal(&models.AuthorizeForm{ClientID: bson.NewObjectId().Hex()})
	_, err := m.AuthorizeResult(getContext(), &models.AuthorizeResultForm{State: base64.StdEncoding.EncodeToString(form)})
	assert.NotNil(t, err)
	assert.Equal(t, "common", err.Code)
	assert.Equal(t, models.ErrorAddAuthLog, err.Message)
}

func TestAuthorizeResultReturnErrorWithCreateOneTimeTokenByExistedUserIdentity(t *testing.T) {
	ip := &mocks.AppIdentityProviderServiceInterface{}
	ui := &mocks.UserIdentityServiceInterface{}
	us := &mocks.UserServiceInterface{}
	as := &mocks.AuthLogServiceInterface{}
	app := &mocks.ApplicationServiceInterface{}
	ott := &mocks.OneTimeTokenServiceInterface{}
	r := &mocks.InternalRegistry{}

	app.On("Get", mock.Anything).Return(&models.Application{}, nil)
	ip.On("FindByTypeAndName", mock.Anything, models.AppIdentityProviderTypeSocial, mock.Anything).Return(&models.AppIdentityProvider{})
	ip.On("GetSocialProfile", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(&models.UserIdentitySocial{ID: "1"}, nil)
	ui.On("Get", mock.Anything, mock.Anything, mock.Anything).Return(&models.UserIdentity{}, nil)
	us.On("Get", mock.Anything).Return(&models.User{}, nil)
	as.On("Add", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)
	ott.On("Create", mock.Anything, mock.Anything).Return(nil, errors.New(""))
	r.On("ApplicationService").Return(app)
	r.On("OneTimeTokenService").Return(ott)

	m := &LoginManager{
		r:                       r,
		identityProviderService: ip,
		userIdentityService:     ui,
		userService:             us,
		authLogService:          as,
	}
	form, _ := json.Marshal(&models.AuthorizeForm{ClientID: bson.NewObjectId().Hex()})
	_, err := m.AuthorizeResult(getContext(), &models.AuthorizeResultForm{State: base64.StdEncoding.EncodeToString(form)})
	assert.NotNil(t, err)
	assert.Equal(t, "common", err.Code)
	assert.Equal(t, models.ErrorCannotCreateToken, err.Message)
}

func TestAuthorizeResultReturnNilOnSuccessResultByExistedUserIdentity(t *testing.T) {
	ip := &mocks.AppIdentityProviderServiceInterface{}
	ui := &mocks.UserIdentityServiceInterface{}
	us := &mocks.UserServiceInterface{}
	as := &mocks.AuthLogServiceInterface{}
	app := &mocks.ApplicationServiceInterface{}
	ott := &mocks.OneTimeTokenServiceInterface{}
	r := &mocks.InternalRegistry{}

	app.On("Get", mock.Anything).Return(&models.Application{}, nil)
	ip.On("FindByTypeAndName", mock.Anything, models.AppIdentityProviderTypeSocial, mock.Anything).Return(&models.AppIdentityProvider{})
	ip.On("GetSocialProfile", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(&models.UserIdentitySocial{ID: "1"}, nil)
	ui.On("Get", mock.Anything, mock.Anything, mock.Anything).Return(&models.UserIdentity{}, nil)
	us.On("Get", mock.Anything).Return(&models.User{}, nil)
	as.On("Add", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)
	ott.On("Create", mock.Anything, mock.Anything).Return(&models.OneTimeToken{}, nil)
	r.On("ApplicationService").Return(app)
	r.On("OneTimeTokenService").Return(ott)

	m := &LoginManager{
		r:                       r,
		identityProviderService: ip,
		userIdentityService:     ui,
		userService:             us,
		authLogService:          as,
	}
	form, _ := json.Marshal(&models.AuthorizeForm{ClientID: bson.NewObjectId().Hex()})
	result, err := m.AuthorizeResult(getContext(), &models.AuthorizeResultForm{State: base64.StdEncoding.EncodeToString(form)})
	assert.Nil(t, err)
	assert.Equal(t, SocialAccountSuccess, result.Result)
}

func TestAuthorizeResultReturnErrorWithUnableToGetDefaultIdentityProvider(t *testing.T) {
	ip := &mocks.AppIdentityProviderServiceInterface{}
	ui := &mocks.UserIdentityServiceInterface{}
	app := &mocks.ApplicationServiceInterface{}
	r := &mocks.InternalRegistry{}

	app.On("Get", mock.Anything).Return(&models.Application{}, nil)
	ip.On("FindByTypeAndName", mock.Anything, models.AppIdentityProviderTypeSocial, mock.Anything).Return(&models.AppIdentityProvider{})
	ip.On("GetSocialProfile", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(&models.UserIdentitySocial{ID: "1", Email: "email"}, nil)
	ui.On("Get", mock.Anything, mock.Anything, mock.Anything).Return(nil, nil)
	ip.On("FindByTypeAndName", mock.Anything, models.AppIdentityProviderTypePassword, models.AppIdentityProviderNameDefault).Return(nil)
	r.On("ApplicationService").Return(app)

	m := &LoginManager{
		r:                       r,
		identityProviderService: ip,
		userIdentityService:     ui,
	}
	form, _ := json.Marshal(&models.AuthorizeForm{ClientID: bson.NewObjectId().Hex()})
	_, err := m.AuthorizeResult(getContext(), &models.AuthorizeResultForm{State: base64.StdEncoding.EncodeToString(form)})
	assert.NotNil(t, err)
	assert.Equal(t, "common", err.Code)
	assert.Equal(t, models.ErrorConnectionIncorrect, err.Message)
}

func TestAuthorizeResultReturnErrorWithUnableToGetUserIdentityForDefaultIdentityProvider(t *testing.T) {
	ip := &mocks.AppIdentityProviderServiceInterface{}
	ui := &mocks.UserIdentityServiceInterface{}
	app := &mocks.ApplicationServiceInterface{}
	r := &mocks.InternalRegistry{}

	app.On("Get", mock.Anything).Return(&models.Application{}, nil)
	ip.On("FindByTypeAndName", mock.Anything, models.AppIdentityProviderTypeSocial, mock.Anything).Return(&models.AppIdentityProvider{})
	ip.On("GetSocialProfile", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(&models.UserIdentitySocial{ID: "1", Email: "email"}, nil)
	ui.On("Get", mock.Anything, mock.Anything, "1").Return(nil, nil)
	ip.On("FindByTypeAndName", mock.Anything, models.AppIdentityProviderTypePassword, models.AppIdentityProviderNameDefault).Return(&models.AppIdentityProvider{})
	ui.On("Get", mock.Anything, mock.Anything, "email").Return(nil, errors.New(""))
	r.On("ApplicationService").Return(app)

	m := &LoginManager{
		r:                       r,
		identityProviderService: ip,
		userIdentityService:     ui,
	}
	form, _ := json.Marshal(&models.AuthorizeForm{ClientID: bson.NewObjectId().Hex()})
	_, err := m.AuthorizeResult(getContext(), &models.AuthorizeResultForm{State: base64.StdEncoding.EncodeToString(form)})
	assert.NotNil(t, err)
	assert.Equal(t, "common", err.Code)
	assert.Equal(t, models.ErrorUnknownError, err.Message)
}

func TestAuthorizeResultReturnErrorWithUnableToLoadSocialSettingsForDefaultIdentityProvider(t *testing.T) {
	ip := &mocks.AppIdentityProviderServiceInterface{}
	ui := &mocks.UserIdentityServiceInterface{}
	app := &mocks.ApplicationServiceInterface{}
	r := &mocks.InternalRegistry{}

	app.On("Get", mock.Anything).Return(&models.Application{}, nil)
	ip.On("FindByTypeAndName", mock.Anything, models.AppIdentityProviderTypeSocial, mock.Anything).Return(&models.AppIdentityProvider{})
	ip.On("GetSocialProfile", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(&models.UserIdentitySocial{ID: "1", Email: "email"}, nil)
	ui.On("Get", mock.Anything, mock.Anything, "1").Return(nil, nil)
	ip.On("FindByTypeAndName", mock.Anything, models.AppIdentityProviderTypePassword, models.AppIdentityProviderNameDefault).Return(&models.AppIdentityProvider{})
	ui.On("Get", mock.Anything, mock.Anything, "email").Return(nil, nil)
	app.On("LoadSocialSettings").Return(nil, errors.New(""))
	r.On("ApplicationService").Return(app)

	m := &LoginManager{
		r:                       r,
		identityProviderService: ip,
		userIdentityService:     ui,
	}
	form, _ := json.Marshal(&models.AuthorizeForm{ClientID: bson.NewObjectId().Hex()})
	_, err := m.AuthorizeResult(getContext(), &models.AuthorizeResultForm{State: base64.StdEncoding.EncodeToString(form)})
	assert.NotNil(t, err)
	assert.Equal(t, "common", err.Code)
	assert.Equal(t, models.ErrorGetSocialSettings, err.Message)
}

func TestAuthorizeResultReturnErrorWithUnableToCreateOneTimeTokenForDefaultIdentityProvider(t *testing.T) {
	ip := &mocks.AppIdentityProviderServiceInterface{}
	ui := &mocks.UserIdentityServiceInterface{}
	app := &mocks.ApplicationServiceInterface{}
	ott := &mocks.OneTimeTokenServiceInterface{}
	r := &mocks.InternalRegistry{}

	app.On("Get", mock.Anything).Return(&models.Application{}, nil)
	ip.On("FindByTypeAndName", mock.Anything, models.AppIdentityProviderTypeSocial, mock.Anything).Return(&models.AppIdentityProvider{ID: bson.NewObjectId()})
	ip.On("GetSocialProfile", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(&models.UserIdentitySocial{ID: "1", Email: "email"}, nil)
	ui.On("Get", mock.Anything, mock.Anything, "1").Return(nil, nil)
	ip.On("FindByTypeAndName", mock.Anything, models.AppIdentityProviderTypePassword, models.AppIdentityProviderNameDefault).Return(&models.AppIdentityProvider{ID: bson.NewObjectId()})
	ui.On("Get", mock.Anything, mock.Anything, "email").Return(&models.UserIdentity{}, nil)
	app.On("LoadSocialSettings").Return(&models.SocialSettings{LinkedTTL: 1, LinkedTokenLength: 2}, nil)
	ott.On("Create", mock.Anything, &models.OneTimeTokenSettings{TTL: 1, Length: 2}).Return(nil, errors.New(""))
	r.On("ApplicationService").Return(app)
	r.On("OneTimeTokenService").Return(ott)

	m := &LoginManager{
		r:                       r,
		identityProviderService: ip,
		userIdentityService:     ui,
	}
	form, _ := json.Marshal(&models.AuthorizeForm{ClientID: bson.NewObjectId().Hex()})
	_, err := m.AuthorizeResult(getContext(), &models.AuthorizeResultForm{State: base64.StdEncoding.EncodeToString(form)})
	assert.NotNil(t, err)
	assert.Equal(t, "common", err.Code)
	assert.Equal(t, models.ErrorCannotCreateToken, err.Message)
}

func TestAuthorizeResultReturnErrorNilOnSuccessCanLinkAccounts(t *testing.T) {
	ip := &mocks.AppIdentityProviderServiceInterface{}
	ui := &mocks.UserIdentityServiceInterface{}
	app := &mocks.ApplicationServiceInterface{}
	ott := &mocks.OneTimeTokenServiceInterface{}
	r := &mocks.InternalRegistry{}

	app.On("Get", mock.Anything).Return(&models.Application{}, nil)
	ip.On("FindByTypeAndName", mock.Anything, models.AppIdentityProviderTypeSocial, mock.Anything).Return(&models.AppIdentityProvider{ID: bson.NewObjectId()})
	ip.On("GetSocialProfile", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(&models.UserIdentitySocial{ID: "1", Email: "email"}, nil)
	ui.On("Get", mock.Anything, mock.Anything, "1").Return(nil, nil)
	ip.On("FindByTypeAndName", mock.Anything, models.AppIdentityProviderTypePassword, models.AppIdentityProviderNameDefault).Return(&models.AppIdentityProvider{ID: bson.NewObjectId()})
	ui.On("Get", mock.Anything, mock.Anything, "email").Return(&models.UserIdentity{}, nil)
	app.On("LoadSocialSettings").Return(&models.SocialSettings{LinkedTTL: 1, LinkedTokenLength: 2}, nil)
	ott.On("Create", mock.Anything, &models.OneTimeTokenSettings{TTL: 1, Length: 2}).Return(&models.OneTimeToken{}, nil)
	r.On("ApplicationService").Return(app)
	r.On("OneTimeTokenService").Return(ott)

	m := &LoginManager{
		r:                       r,
		identityProviderService: ip,
		userIdentityService:     ui,
	}
	form, _ := json.Marshal(&models.AuthorizeForm{ClientID: bson.NewObjectId().Hex()})
	result, err := m.AuthorizeResult(getContext(), &models.AuthorizeResultForm{State: base64.StdEncoding.EncodeToString(form)})
	assert.Nil(t, err)
	assert.Equal(t, SocialAccountCanLink, result.Result)
}

func TestAuthorizeResultReturnErrorWithUnableToCreateUser(t *testing.T) {
	ip := &mocks.AppIdentityProviderServiceInterface{}
	ui := &mocks.UserIdentityServiceInterface{}
	app := &mocks.ApplicationServiceInterface{}
	us := &mocks.UserServiceInterface{}
	r := &mocks.InternalRegistry{}

	app.On("Get", mock.Anything).Return(&models.Application{}, nil)
	ip.On("FindByTypeAndName", mock.Anything, models.AppIdentityProviderTypeSocial, mock.Anything).Return(&models.AppIdentityProvider{})
	ip.On("GetSocialProfile", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(&models.UserIdentitySocial{ID: "1"}, nil)
	ui.On("Get", mock.Anything, mock.Anything, mock.Anything).Return(nil, nil)
	us.On("Create", mock.Anything).Return(errors.New(""))
	r.On("ApplicationService").Return(app)

	m := &LoginManager{
		r:                       r,
		identityProviderService: ip,
		userIdentityService:     ui,
		userService:             us,
	}
	form, _ := json.Marshal(&models.AuthorizeForm{ClientID: bson.NewObjectId().Hex()})
	_, err := m.AuthorizeResult(getContext(), &models.AuthorizeResultForm{State: base64.StdEncoding.EncodeToString(form)})
	assert.NotNil(t, err)
	assert.Equal(t, "common", err.Code)
	assert.Equal(t, models.ErrorCreateUser, err.Message)
}

func TestAuthorizeResultReturnErrorWithUnableToCreateUserIdentity(t *testing.T) {
	ip := &mocks.AppIdentityProviderServiceInterface{}
	ui := &mocks.UserIdentityServiceInterface{}
	app := &mocks.ApplicationServiceInterface{}
	us := &mocks.UserServiceInterface{}
	r := &mocks.InternalRegistry{}

	app.On("Get", mock.Anything).Return(&models.Application{}, nil)
	ip.On("FindByTypeAndName", mock.Anything, models.AppIdentityProviderTypeSocial, mock.Anything).Return(&models.AppIdentityProvider{})
	ip.On("GetSocialProfile", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(&models.UserIdentitySocial{ID: "1"}, nil)
	ui.On("Get", mock.Anything, mock.Anything, mock.Anything).Return(nil, nil)
	us.On("Create", mock.Anything).Return(nil)
	ui.On("Create", mock.Anything).Return(errors.New(""))
	r.On("ApplicationService").Return(app)

	m := &LoginManager{
		r:                       r,
		identityProviderService: ip,
		userIdentityService:     ui,
		userService:             us,
	}
	form, _ := json.Marshal(&models.AuthorizeForm{ClientID: bson.NewObjectId().Hex()})
	_, err := m.AuthorizeResult(getContext(), &models.AuthorizeResultForm{State: base64.StdEncoding.EncodeToString(form)})
	assert.NotNil(t, err)
	assert.Equal(t, "common", err.Code)
	assert.Equal(t, models.ErrorCreateUserIdentity, err.Message)
}

func TestAuthorizeResultReturnErrorWithUnableToAddAuthLogForNewUserAccount(t *testing.T) {
	ip := &mocks.AppIdentityProviderServiceInterface{}
	ui := &mocks.UserIdentityServiceInterface{}
	app := &mocks.ApplicationServiceInterface{}
	as := &mocks.AuthLogServiceInterface{}
	us := &mocks.UserServiceInterface{}
	r := &mocks.InternalRegistry{}

	app.On("Get", mock.Anything).Return(&models.Application{}, nil)
	ip.On("FindByTypeAndName", mock.Anything, models.AppIdentityProviderTypeSocial, mock.Anything).Return(&models.AppIdentityProvider{})
	ip.On("GetSocialProfile", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(&models.UserIdentitySocial{ID: "1"}, nil)
	ui.On("Get", mock.Anything, mock.Anything, mock.Anything).Return(nil, nil)
	us.On("Create", mock.Anything).Return(nil)
	ui.On("Create", mock.Anything).Return(nil)
	as.On("Add", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(errors.New(""))
	r.On("ApplicationService").Return(app)

	m := &LoginManager{
		r:                       r,
		identityProviderService: ip,
		userIdentityService:     ui,
		userService:             us,
		authLogService:          as,
	}
	form, _ := json.Marshal(&models.AuthorizeForm{ClientID: bson.NewObjectId().Hex()})
	_, err := m.AuthorizeResult(getContext(), &models.AuthorizeResultForm{State: base64.StdEncoding.EncodeToString(form)})
	assert.NotNil(t, err)
	assert.Equal(t, "common", err.Code)
	assert.Equal(t, models.ErrorAddAuthLog, err.Message)
}

func TestAuthorizeResultReturnErrorWithUnableToCreateOneTimeTokenForNewUserAccount(t *testing.T) {
	ip := &mocks.AppIdentityProviderServiceInterface{}
	ui := &mocks.UserIdentityServiceInterface{}
	app := &mocks.ApplicationServiceInterface{}
	as := &mocks.AuthLogServiceInterface{}
	us := &mocks.UserServiceInterface{}
	ott := &mocks.OneTimeTokenServiceInterface{}
	r := &mocks.InternalRegistry{}

	app.On("Get", mock.Anything).Return(&models.Application{}, nil)
	ip.On("FindByTypeAndName", mock.Anything, models.AppIdentityProviderTypeSocial, mock.Anything).Return(&models.AppIdentityProvider{})
	ip.On("GetSocialProfile", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(&models.UserIdentitySocial{ID: "1"}, nil)
	ui.On("Get", mock.Anything, mock.Anything, mock.Anything).Return(nil, nil)
	us.On("Create", mock.Anything).Return(nil)
	ui.On("Create", mock.Anything).Return(nil)
	as.On("Add", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)
	ott.On("Create", mock.Anything, mock.Anything).Return(nil, errors.New(""))
	r.On("ApplicationService").Return(app)
	r.On("OneTimeTokenService").Return(ott)

	m := &LoginManager{
		r:                       r,
		identityProviderService: ip,
		userIdentityService:     ui,
		userService:             us,
		authLogService:          as,
	}
	form, _ := json.Marshal(&models.AuthorizeForm{ClientID: bson.NewObjectId().Hex()})
	_, err := m.AuthorizeResult(getContext(), &models.AuthorizeResultForm{State: base64.StdEncoding.EncodeToString(form)})
	assert.NotNil(t, err)
	assert.Equal(t, "common", err.Code)
	assert.Equal(t, models.ErrorCannotCreateToken, err.Message)
}

func TestAuthorizeResultReturnSuccessOnCreateNewUserAccount(t *testing.T) {
	ip := &mocks.AppIdentityProviderServiceInterface{}
	ui := &mocks.UserIdentityServiceInterface{}
	app := &mocks.ApplicationServiceInterface{}
	as := &mocks.AuthLogServiceInterface{}
	us := &mocks.UserServiceInterface{}
	ott := &mocks.OneTimeTokenServiceInterface{}
	r := &mocks.InternalRegistry{}

	app.On("Get", mock.Anything).Return(&models.Application{}, nil)
	ip.On("FindByTypeAndName", mock.Anything, models.AppIdentityProviderTypeSocial, mock.Anything).Return(&models.AppIdentityProvider{})
	ip.On("GetSocialProfile", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(&models.UserIdentitySocial{ID: "1"}, nil)
	ui.On("Get", mock.Anything, mock.Anything, mock.Anything).Return(nil, nil)
	us.On("Create", mock.Anything).Return(nil)
	ui.On("Create", mock.Anything).Return(nil)
	as.On("Add", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)
	ott.On("Create", mock.Anything, mock.Anything).Return(&models.OneTimeToken{}, nil)
	r.On("ApplicationService").Return(app)
	r.On("OneTimeTokenService").Return(ott)

	m := &LoginManager{
		r:                       r,
		identityProviderService: ip,
		userIdentityService:     ui,
		userService:             us,
		authLogService:          as,
	}
	form, _ := json.Marshal(&models.AuthorizeForm{ClientID: bson.NewObjectId().Hex()})
	result, err := m.AuthorizeResult(getContext(), &models.AuthorizeResultForm{State: base64.StdEncoding.EncodeToString(form)})
	assert.Nil(t, err)
	assert.Equal(t, SocialAccountSuccess, result.Result)
}

func TestAuthorizeLinkReturnErrorWithIncorrectClient(t *testing.T) {
	app := &mocks.ApplicationServiceInterface{}
	r := &mocks.InternalRegistry{}

	app.On("Get", mock.Anything).Return(nil, errors.New(""))
	r.On("ApplicationService").Return(app)

	m := &LoginManager{r: r}
	_, err := m.AuthorizeLink(getContext(), &models.AuthorizeLinkForm{ClientID: bson.NewObjectId().Hex()})
	assert.NotNil(t, err)
	assert.Equal(t, "client_id", err.Code)
	assert.Equal(t, models.ErrorClientIdIncorrect, err.Message)
}

func TestAuthorizeLinkReturnErrorWithUseToken(t *testing.T) {
	app := &mocks.ApplicationServiceInterface{}
	ott := &mocks.OneTimeTokenServiceInterface{}
	r := &mocks.InternalRegistry{}

	app.On("Get", mock.Anything).Return(&models.Application{}, nil)
	ott.On("Use", "code", mock.Anything).Return(errors.New(""))
	r.On("ApplicationService").Return(app)
	r.On("OneTimeTokenService").Return(ott)

	m := &LoginManager{r: r}
	_, err := m.AuthorizeLink(getContext(), &models.AuthorizeLinkForm{ClientID: bson.NewObjectId().Hex(), Code: "code"})
	assert.NotNil(t, err)
	assert.Equal(t, "common", err.Code)
	assert.Equal(t, models.ErrorCannotUseToken, err.Message)
}

func TestAuthorizeLinkCaseLinkReturnErrorWithInvalidPassword(t *testing.T) {
	app := &mocks.ApplicationServiceInterface{}
	ott := &mocks.OneTimeTokenServiceInterface{}
	r := &mocks.InternalRegistry{}

	passSettings := &models.PasswordSettings{Min: 5, Max: 8, RequireSpecial: false, RequireUpper: false, RequireNumber: false}
	app.On("Get", mock.Anything).Return(&models.Application{ID: bson.NewObjectId(), PasswordSettings: passSettings}, nil)
	ott.On("Use", "code", mock.Anything).Return(nil)
	r.On("ApplicationService").Return(app)
	r.On("OneTimeTokenService").Return(ott)

	m := &LoginManager{r: r}
	_, err := m.AuthorizeLink(getContext(), &models.AuthorizeLinkForm{ClientID: bson.NewObjectId().Hex(), Code: "code", Action: "link", Password: "1234"})
	assert.NotNil(t, err)
	assert.Equal(t, "password", err.Code)
	assert.Equal(t, models.ErrorPasswordIncorrect, err.Message)
}

func TestAuthorizeLinkCaseLinkReturnErrorWithUnavailableIdentityProvider(t *testing.T) {
	app := &mocks.ApplicationServiceInterface{}
	ott := &mocks.OneTimeTokenServiceInterface{}
	ip := &mocks.AppIdentityProviderServiceInterface{}
	r := &mocks.InternalRegistry{}

	passSettings := &models.PasswordSettings{Min: 4, Max: 8, RequireSpecial: false, RequireUpper: false, RequireNumber: false}
	app.On("Get", mock.Anything).Return(&models.Application{ID: bson.NewObjectId(), PasswordSettings: passSettings}, nil)
	ott.On("Use", "code", mock.Anything).Return(nil)
	ip.On("FindByTypeAndName", mock.Anything, models.AppIdentityProviderTypePassword, models.AppIdentityProviderNameDefault).Return(nil)
	r.On("ApplicationService").Return(app)
	r.On("OneTimeTokenService").Return(ott)

	m := &LoginManager{
		r:                       r,
		identityProviderService: ip,
	}
	_, err := m.AuthorizeLink(getContext(), &models.AuthorizeLinkForm{ClientID: bson.NewObjectId().Hex(), Code: "code", Action: "link", Password: "1234"})
	assert.NotNil(t, err)
	assert.Equal(t, "client_id", err.Code)
	assert.Equal(t, models.ErrorClientIdIncorrect, err.Message)
}

func TestAuthorizeLinkCaseLinkReturnErrorWithEmptyUserIdentity(t *testing.T) {
	app := &mocks.ApplicationServiceInterface{}
	ott := &mocks.OneTimeTokenServiceInterface{}
	ip := &mocks.AppIdentityProviderServiceInterface{}
	ui := &mocks.UserIdentityServiceInterface{}
	r := &mocks.InternalRegistry{}

	passSettings := &models.PasswordSettings{Min: 4, Max: 8, RequireSpecial: false, RequireUpper: false, RequireNumber: false}
	app.On("Get", mock.Anything).Return(&models.Application{ID: bson.NewObjectId(), PasswordSettings: passSettings}, nil)
	ott.On("Use", "code", mock.Anything).Return(nil)
	ip.On("FindByTypeAndName", mock.Anything, mock.Anything, mock.Anything).Return(&models.AppIdentityProvider{})
	ui.On("Get", mock.Anything, mock.Anything, mock.Anything).Return(nil, errors.New(""))
	r.On("ApplicationService").Return(app)
	r.On("OneTimeTokenService").Return(ott)

	m := &LoginManager{
		r:                       r,
		identityProviderService: ip,
		userIdentityService:     ui,
	}
	_, err := m.AuthorizeLink(getContext(), &models.AuthorizeLinkForm{ClientID: bson.NewObjectId().Hex(), Code: "code", Action: "link", Password: "1234"})
	assert.NotNil(t, err)
	assert.Equal(t, "client_id", err.Code)
	assert.Equal(t, models.ErrorClientIdIncorrect, err.Message)
}

func TestAuthorizeLinkCaseLinkReturnErrorWithComparePassword(t *testing.T) {
	app := &mocks.ApplicationServiceInterface{}
	ott := &mocks.OneTimeTokenServiceInterface{}
	ip := &mocks.AppIdentityProviderServiceInterface{}
	ui := &mocks.UserIdentityServiceInterface{}
	r := &mocks.InternalRegistry{}

	passSettings := &models.PasswordSettings{Min: 1, Max: 8, RequireSpecial: false, RequireUpper: false, RequireNumber: false, BcryptCost: 32}
	app.On("Get", mock.Anything).Return(&models.Application{ID: bson.NewObjectId(), PasswordSettings: passSettings}, nil)
	ott.On("Use", "code", mock.Anything).Return(nil)
	ip.On("FindByTypeAndName", mock.Anything, mock.Anything, mock.Anything).Return(&models.AppIdentityProvider{})
	ui.On("Get", mock.Anything, mock.Anything, mock.Anything).Return(&models.UserIdentity{ID: bson.NewObjectId(), Credential: "123"}, nil)
	r.On("ApplicationService").Return(app)
	r.On("OneTimeTokenService").Return(ott)

	m := &LoginManager{
		r:                       r,
		identityProviderService: ip,
		userIdentityService:     ui,
	}
	_, err := m.AuthorizeLink(getContext(), &models.AuthorizeLinkForm{ClientID: bson.NewObjectId().Hex(), Code: "code", Action: "link", Password: "1234"})
	assert.NotNil(t, err)
	assert.Equal(t, "password", err.Code)
	assert.Equal(t, models.ErrorPasswordIncorrect, err.Message)
}

func TestAuthorizeLinkCaseLinkReturnErrorWithUnableToGetMfaProviders(t *testing.T) {
	app := &mocks.ApplicationServiceInterface{}
	ott := &mocks.OneTimeTokenServiceInterface{}
	ip := &mocks.AppIdentityProviderServiceInterface{}
	ui := &mocks.UserIdentityServiceInterface{}
	mfa := &mocks.MfaServiceInterface{}
	r := &mocks.InternalRegistry{}

	passSettings := &models.PasswordSettings{Min: 1, Max: 8, RequireSpecial: false, RequireUpper: false, RequireNumber: false, BcryptCost: 4}
	be := models.NewBcryptEncryptor(&models.CryptConfig{Cost: passSettings.BcryptCost})
	passHash, _ := be.Digest("1234")

	app.On("Get", mock.Anything).Return(&models.Application{ID: bson.NewObjectId(), PasswordSettings: passSettings}, nil)
	ott.On("Use", "code", mock.Anything).Return(nil)
	ip.On("FindByTypeAndName", mock.Anything, mock.Anything, mock.Anything).Return(&models.AppIdentityProvider{})
	ui.On("Get", mock.Anything, mock.Anything, mock.Anything).Return(&models.UserIdentity{ID: bson.NewObjectId(), Credential: passHash}, nil)
	mfa.On("GetUserProviders", mock.Anything).Return(nil, errors.New(""))
	r.On("ApplicationService").Return(app)
	r.On("OneTimeTokenService").Return(ott)

	m := &LoginManager{
		r:                       r,
		identityProviderService: ip,
		userIdentityService:     ui,
		mfaService:              mfa,
	}
	_, err := m.AuthorizeLink(getContext(), &models.AuthorizeLinkForm{ClientID: bson.NewObjectId().Hex(), Code: "code", Action: "link", Password: "1234"})
	assert.NotNil(t, err)
	assert.Equal(t, "common", err.Code)
	assert.Equal(t, models.ErrorUnknownError, err.Message)
}

func TestAuthorizeLinkCaseLinkReturnErrorWithHaveMfaAndFailOnCreateOneTimeToken(t *testing.T) {
	app := &mocks.ApplicationServiceInterface{}
	ott := &mocks.OneTimeTokenServiceInterface{}
	ip := &mocks.AppIdentityProviderServiceInterface{}
	ui := &mocks.UserIdentityServiceInterface{}
	mfa := &mocks.MfaServiceInterface{}
	r := &mocks.InternalRegistry{}

	passSettings := &models.PasswordSettings{Min: 1, Max: 8, RequireSpecial: false, RequireUpper: false, RequireNumber: false, BcryptCost: 4}
	be := models.NewBcryptEncryptor(&models.CryptConfig{Cost: passSettings.BcryptCost})
	passHash, _ := be.Digest("1234")

	app.On("Get", mock.Anything).Return(&models.Application{ID: bson.NewObjectId(), PasswordSettings: passSettings}, nil)
	ott.On("Use", "code", mock.Anything).Return(nil)
	ip.On("FindByTypeAndName", mock.Anything, mock.Anything, mock.Anything).Return(&models.AppIdentityProvider{})
	ui.On("Get", mock.Anything, mock.Anything, mock.Anything).Return(&models.UserIdentity{ID: bson.NewObjectId(), Credential: passHash}, nil)
	mfa.On("GetUserProviders", mock.Anything).Return([]*models.MfaProvider{{}}, nil)
	ott.On("Create", mock.Anything, mock.Anything).Return(nil, errors.New(""))
	r.On("ApplicationService").Return(app)
	r.On("OneTimeTokenService").Return(ott)

	m := &LoginManager{
		r:                       r,
		identityProviderService: ip,
		userIdentityService:     ui,
		mfaService:              mfa,
	}
	_, err := m.AuthorizeLink(getContext(), &models.AuthorizeLinkForm{ClientID: bson.NewObjectId().Hex(), Code: "code", Action: "link", Password: "1234"})
	assert.NotNil(t, err)
	assert.Equal(t, "common", err.Code)
	assert.Equal(t, models.ErrorCannotCreateToken, err.Message)
}

func TestAuthorizeLinkCaseLinkReturnErrorWithHaveMfaAndReturnOneTimeToken(t *testing.T) {
	app := &mocks.ApplicationServiceInterface{}
	ott := &mocks.OneTimeTokenServiceInterface{}
	ip := &mocks.AppIdentityProviderServiceInterface{}
	ui := &mocks.UserIdentityServiceInterface{}
	mfa := &mocks.MfaServiceInterface{}
	r := &mocks.InternalRegistry{}

	passSettings := &models.PasswordSettings{Min: 1, Max: 8, RequireSpecial: false, RequireUpper: false, RequireNumber: false, BcryptCost: 4}
	be := models.NewBcryptEncryptor(&models.CryptConfig{Cost: passSettings.BcryptCost})
	passHash, _ := be.Digest("1234")

	app.On("Get", mock.Anything).Return(&models.Application{ID: bson.NewObjectId(), PasswordSettings: passSettings}, nil)
	ott.On("Use", "code", mock.Anything).Return(nil)
	ip.On("FindByTypeAndName", mock.Anything, mock.Anything, mock.Anything).Return(&models.AppIdentityProvider{})
	ui.On("Get", mock.Anything, mock.Anything, mock.Anything).Return(&models.UserIdentity{ID: bson.NewObjectId(), Credential: passHash}, nil)
	mfa.On("GetUserProviders", mock.Anything).Return([]*models.MfaProvider{{}}, nil)
	ott.On("Create", mock.Anything, mock.Anything).Return(&models.OneTimeToken{Token: "ott"}, nil)
	r.On("ApplicationService").Return(app)
	r.On("OneTimeTokenService").Return(ott)

	m := &LoginManager{
		r:                       r,
		identityProviderService: ip,
		userIdentityService:     ui,
		mfaService:              mfa,
	}
	_, err := m.AuthorizeLink(getContext(), &models.AuthorizeLinkForm{ClientID: bson.NewObjectId().Hex(), Code: "code", Action: "link", Password: "1234"})
	assert.NotNil(t, err)
	assert.Equal(t, "common", err.Code)
	assert.Equal(t, "ott", err.Message)
}

func TestAuthorizeLinkCaseLinkReturnErrorWithDontHaveMfaAndUnableToGetUser(t *testing.T) {
	app := &mocks.ApplicationServiceInterface{}
	ott := &mocks.OneTimeTokenServiceInterface{}
	ip := &mocks.AppIdentityProviderServiceInterface{}
	ui := &mocks.UserIdentityServiceInterface{}
	mfa := &mocks.MfaServiceInterface{}
	us := &mocks.UserServiceInterface{}
	r := &mocks.InternalRegistry{}

	passSettings := &models.PasswordSettings{Min: 1, Max: 8, RequireSpecial: false, RequireUpper: false, RequireNumber: false, BcryptCost: 4}
	be := models.NewBcryptEncryptor(&models.CryptConfig{Cost: passSettings.BcryptCost})
	passHash, _ := be.Digest("1234")

	app.On("Get", mock.Anything).Return(&models.Application{ID: bson.NewObjectId(), PasswordSettings: passSettings}, nil)
	ott.On("Use", "code", mock.Anything).Return(nil)
	ip.On("FindByTypeAndName", mock.Anything, mock.Anything, mock.Anything).Return(&models.AppIdentityProvider{})
	ui.On("Get", mock.Anything, mock.Anything, mock.Anything).Return(&models.UserIdentity{ID: bson.NewObjectId(), Credential: passHash}, nil)
	mfa.On("GetUserProviders", mock.Anything).Return(nil, nil)
	us.On("Get", mock.Anything).Return(nil, errors.New(""))
	r.On("ApplicationService").Return(app)
	r.On("OneTimeTokenService").Return(ott)

	m := &LoginManager{
		r:                       r,
		identityProviderService: ip,
		userIdentityService:     ui,
		mfaService:              mfa,
		userService:             us,
	}
	_, err := m.AuthorizeLink(getContext(), &models.AuthorizeLinkForm{ClientID: bson.NewObjectId().Hex(), Code: "code", Action: "link", Password: "1234"})
	assert.NotNil(t, err)
	assert.Equal(t, "email", err.Code)
	assert.Equal(t, models.ErrorLoginIncorrect, err.Message)
}

func TestAuthorizeLinkCaseNewReturnErrorWithUnableToCreateUser(t *testing.T) {
	app := &mocks.ApplicationServiceInterface{}
	ott := &mocks.OneTimeTokenServiceInterface{}
	ip := &mocks.AppIdentityProviderServiceInterface{}
	us := &mocks.UserServiceInterface{}
	r := &mocks.InternalRegistry{}

	app.On("Get", mock.Anything).Return(&models.Application{ID: bson.NewObjectId()}, nil)
	ott.On("Use", "code", mock.Anything).Return(nil)
	ip.On("FindByTypeAndName", mock.Anything, mock.Anything, mock.Anything).Return(&models.AppIdentityProvider{})
	us.On("Create", mock.Anything).Return(errors.New(""))
	r.On("ApplicationService").Return(app)
	r.On("OneTimeTokenService").Return(ott)

	m := &LoginManager{
		r:                       r,
		identityProviderService: ip,
		userService:             us,
	}
	_, err := m.AuthorizeLink(getContext(), &models.AuthorizeLinkForm{ClientID: bson.NewObjectId().Hex(), Code: "code", Action: "new"})
	assert.NotNil(t, err)
	assert.Equal(t, "common", err.Code)
	assert.Equal(t, models.ErrorCreateUser, err.Message)
}

func TestAuthorizeLinkCaseUnknownReturnError(t *testing.T) {
	app := &mocks.ApplicationServiceInterface{}
	ott := &mocks.OneTimeTokenServiceInterface{}
	ip := &mocks.AppIdentityProviderServiceInterface{}
	r := &mocks.InternalRegistry{}

	app.On("Get", mock.Anything).Return(&models.Application{ID: bson.NewObjectId()}, nil)
	ott.On("Use", "code", mock.Anything).Return(nil)
	ip.On("FindByTypeAndName", mock.Anything, mock.Anything, mock.Anything).Return(&models.AppIdentityProvider{})
	r.On("ApplicationService").Return(app)
	r.On("OneTimeTokenService").Return(ott)

	m := &LoginManager{
		r:                       r,
		identityProviderService: ip,
	}
	_, err := m.AuthorizeLink(getContext(), &models.AuthorizeLinkForm{ClientID: bson.NewObjectId().Hex(), Code: "code", Action: "unknown"})
	assert.NotNil(t, err)
	assert.Equal(t, "common", err.Code)
	assert.Equal(t, models.ErrorUnknownError, err.Message)
}

func TestAuthorizeLinkReturnErrorWithUnableToCreateUserIdentity(t *testing.T) {
	app := &mocks.ApplicationServiceInterface{}
	ott := &mocks.OneTimeTokenServiceInterface{}
	ip := &mocks.AppIdentityProviderServiceInterface{}
	us := &mocks.UserServiceInterface{}
	ui := &mocks.UserIdentityServiceInterface{}
	r := &mocks.InternalRegistry{}

	app.On("Get", mock.Anything).Return(&models.Application{ID: bson.NewObjectId()}, nil)
	ott.On("Use", "code", mock.Anything).Return(nil)
	ip.On("FindByTypeAndName", mock.Anything, mock.Anything, mock.Anything).Return(&models.AppIdentityProvider{})
	us.On("Create", mock.Anything).Return(nil)
	ui.On("Create", mock.Anything).Return(errors.New(""))
	r.On("ApplicationService").Return(app)
	r.On("OneTimeTokenService").Return(ott)

	m := &LoginManager{
		r:                       r,
		identityProviderService: ip,
		userService:             us,
		userIdentityService:     ui,
	}
	_, err := m.AuthorizeLink(getContext(), &models.AuthorizeLinkForm{ClientID: bson.NewObjectId().Hex(), Code: "code", Action: "new"})
	assert.NotNil(t, err)
	assert.Equal(t, "common", err.Code)
	assert.Equal(t, models.ErrorCreateUserIdentity, err.Message)
}

func TestAuthorizeLinkReturnErrorWithUnableToCreateAuthLog(t *testing.T) {
	app := &mocks.ApplicationServiceInterface{}
	ott := &mocks.OneTimeTokenServiceInterface{}
	ip := &mocks.AppIdentityProviderServiceInterface{}
	us := &mocks.UserServiceInterface{}
	ui := &mocks.UserIdentityServiceInterface{}
	as := &mocks.AuthLogServiceInterface{}
	r := &mocks.InternalRegistry{}

	app.On("Get", mock.Anything).Return(&models.Application{ID: bson.NewObjectId()}, nil)
	ott.On("Use", "code", mock.Anything).Return(nil)
	ip.On("FindByTypeAndName", mock.Anything, mock.Anything, mock.Anything).Return(&models.AppIdentityProvider{})
	us.On("Create", mock.Anything).Return(nil)
	ui.On("Create", mock.Anything).Return(nil)
	as.On("Add", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(errors.New(""))
	r.On("ApplicationService").Return(app)
	r.On("OneTimeTokenService").Return(ott)

	m := &LoginManager{
		r:                       r,
		identityProviderService: ip,
		userService:             us,
		userIdentityService:     ui,
		authLogService:          as,
	}
	_, err := m.AuthorizeLink(getContext(), &models.AuthorizeLinkForm{ClientID: bson.NewObjectId().Hex(), Code: "code", Action: "new"})
	assert.NotNil(t, err)
	assert.Equal(t, "common", err.Code)
	assert.Equal(t, models.ErrorAddAuthLog, err.Message)
}

func TestAuthorizeLinkReturnErrorWithUnableToAcceptHydraLoginRequest(t *testing.T) {
	app := &mocks.ApplicationServiceInterface{}
	ott := &mocks.OneTimeTokenServiceInterface{}
	ip := &mocks.AppIdentityProviderServiceInterface{}
	us := &mocks.UserServiceInterface{}
	ui := &mocks.UserIdentityServiceInterface{}
	as := &mocks.AuthLogServiceInterface{}
	h := &mocks.HydraAdminApi{}
	r := &mocks.InternalRegistry{}

	app.On("Get", mock.Anything).Return(&models.Application{ID: bson.NewObjectId()}, nil)
	ott.On("Use", "code", mock.Anything).Return(nil)
	ip.On("FindByTypeAndName", mock.Anything, mock.Anything, mock.Anything).Return(&models.AppIdentityProvider{})
	us.On("Create", mock.Anything).Return(nil)
	ui.On("Create", mock.Anything).Return(nil)
	as.On("Add", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)
	h.On("AcceptLoginRequest", mock.Anything).Return(nil, errors.New(""))
	r.On("ApplicationService").Return(app)
	r.On("OneTimeTokenService").Return(ott)
	r.On("HydraAdminApi").Return(h)

	m := &LoginManager{
		r:                       r,
		identityProviderService: ip,
		userService:             us,
		userIdentityService:     ui,
		authLogService:          as,
	}
	_, err := m.AuthorizeLink(getContext(), &models.AuthorizeLinkForm{ClientID: bson.NewObjectId().Hex(), Code: "code", Action: "new"})
	assert.NotNil(t, err)
	assert.Equal(t, "common", err.Code)
	assert.Equal(t, models.ErrorUnknownError, err.Message)
}

func TestAuthorizeLinkReturnUrlOnSuccessResult(t *testing.T) {
	app := &mocks.ApplicationServiceInterface{}
	ott := &mocks.OneTimeTokenServiceInterface{}
	ip := &mocks.AppIdentityProviderServiceInterface{}
	us := &mocks.UserServiceInterface{}
	ui := &mocks.UserIdentityServiceInterface{}
	as := &mocks.AuthLogServiceInterface{}
	h := &mocks.HydraAdminApi{}
	r := &mocks.InternalRegistry{}

	app.On("Get", mock.Anything).Return(&models.Application{ID: bson.NewObjectId()}, nil)
	ott.On("Use", "code", mock.Anything).Return(nil)
	ip.On("FindByTypeAndName", mock.Anything, mock.Anything, mock.Anything).Return(&models.AppIdentityProvider{})
	us.On("Create", mock.Anything).Return(nil)
	ui.On("Create", mock.Anything).Return(nil)
	as.On("Add", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)
	h.On("AcceptLoginRequest", mock.Anything).Return(&admin.AcceptLoginRequestOK{Payload: &models2.RequestHandlerResponse{RedirectTo: "url"}}, nil)
	r.On("ApplicationService").Return(app)
	r.On("OneTimeTokenService").Return(ott)
	r.On("HydraAdminApi").Return(h)

	m := &LoginManager{
		r:                       r,
		identityProviderService: ip,
		userService:             us,
		userIdentityService:     ui,
		authLogService:          as,
	}
	url, err := m.AuthorizeLink(getContext(), &models.AuthorizeLinkForm{ClientID: bson.NewObjectId().Hex(), Code: "code", Action: "new"})
	assert.Nil(t, err)
	assert.Equal(t, "url", url)
}

func getContext(args ...map[string]interface{}) echo.Context {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/url", strings.NewReader(""))
	rec := httptest.NewRecorder()

	for _, values := range args {
		if _, ok := values["headers"]; ok {
			headers := values["headers"].(map[string]interface{})
			for key, value := range headers {
				req.Header.Set(key, value.(string))
			}
		}
	}

	return e.NewContext(req, rec)
}
