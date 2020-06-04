package manager

import (
	"testing"

	"github.com/ProtocolONE/auth1.protocol.one/pkg/config"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/mocks"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/models"
	"github.com/globalsign/mgo"
	"github.com/globalsign/mgo/bson"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestChangePasswordManager(t *testing.T) {
	s := &mocks.MgoSession{}
	s.On("DB", mock.Anything).Return(&mgo.Database{})
	r := &mocks.InternalRegistry{}
	r.On("SpaceService").Return(nil)
	r.On("Spaces").Return(nil)
	m := NewChangePasswordManager(s, r, nil, nil)
	assert.Implements(t, (*ChangePasswordManagerInterface)(nil), m)
}

func TestChangePasswordStartReturnErrorWithIncorrectClient(t *testing.T) {
	app := &mocks.ApplicationServiceInterface{}
	r := &mocks.InternalRegistry{}

	app.On("Get", mock.Anything).Return(nil, errors.New(""))
	r.On("ApplicationService").Return(app)

	m := &ChangePasswordManager{r: r}
	err := m.ChangePasswordStart(&models.ChangePasswordStartForm{ClientID: bson.NewObjectId().Hex()})
	assert.NotNil(t, err)
	assert.Equal(t, "client_id", err.Code)
	assert.Equal(t, models.ErrorClientIdIncorrect, err.Message)
}

func TestChangePasswordStartReturnErrorWithUnavailableIdentityProvider(t *testing.T) {
	ip := &mocks.AppIdentityProviderServiceInterface{}
	app := &mocks.ApplicationServiceInterface{}
	r := &mocks.InternalRegistry{}

	app.On("Get", mock.Anything).Return(&models.Application{}, nil)
	ip.On("FindByTypeAndName", mock.Anything, models.AppIdentityProviderTypePassword, models.AppIdentityProviderNameDefault).Return(nil)
	r.On("ApplicationService").Return(app)

	m := &ChangePasswordManager{
		r:                       r,
		identityProviderService: ip,
	}
	err := m.ChangePasswordStart(&models.ChangePasswordStartForm{ClientID: bson.NewObjectId().Hex()})
	assert.NotNil(t, err)
	assert.Equal(t, "client_id", err.Code)
	assert.Equal(t, models.ErrorUnknownError, err.Message)
}

func TestChangePasswordStartReturnErrorWithErrorOnUserIdentity(t *testing.T) {
	ip := &mocks.AppIdentityProviderServiceInterface{}
	ui := &mocks.UserIdentityServiceInterface{}
	app := &mocks.ApplicationServiceInterface{}
	r := &mocks.InternalRegistry{}

	app.On("Get", mock.Anything).Return(&models.Application{}, nil)
	ip.On("FindByTypeAndName", mock.Anything, mock.Anything, mock.Anything).Return(&models.AppIdentityProvider{})
	ui.On("Get", mock.Anything, mock.Anything, mock.Anything).Return(nil, errors.New(""))
	r.On("ApplicationService").Return(app)

	m := &ChangePasswordManager{
		r:                       r,
		userIdentityService:     ui,
		identityProviderService: ip,
	}
	err := m.ChangePasswordStart(&models.ChangePasswordStartForm{ClientID: bson.NewObjectId().Hex()})
	assert.NotNil(t, err)
	assert.Equal(t, "email", err.Code)
	assert.Equal(t, models.ErrorUnknownError, err.Message)
}

func TestChangePasswordStartReturnNilIfUserNotFound(t *testing.T) {
	ip := &mocks.AppIdentityProviderServiceInterface{}
	ui := &mocks.UserIdentityServiceInterface{}
	app := &mocks.ApplicationServiceInterface{}
	r := &mocks.InternalRegistry{}

	app.On("Get", mock.Anything).Return(&models.Application{}, nil)
	ip.On("FindByTypeAndName", mock.Anything, mock.Anything, mock.Anything).Return(&models.AppIdentityProvider{})
	ui.On("Get", mock.Anything, mock.Anything, mock.Anything).Return(&models.UserIdentity{}, nil)
	r.On("ApplicationService").Return(app)

	m := &ChangePasswordManager{
		r:                       r,
		userIdentityService:     ui,
		identityProviderService: ip,
	}
	err := m.ChangePasswordStart(&models.ChangePasswordStartForm{ClientID: bson.NewObjectId().Hex()})
	assert.Nil(t, err)
}

func TestChangePasswordStartReturnErrorOnCreateToken(t *testing.T) {
	ip := &mocks.AppIdentityProviderServiceInterface{}
	ui := &mocks.UserIdentityServiceInterface{}
	app := &mocks.ApplicationServiceInterface{}
	ott := &mocks.OneTimeTokenServiceInterface{}
	r := &mocks.InternalRegistry{}

	app.On("Get", mock.Anything).Return(&models.Application{PasswordSettings: &models.PasswordSettings{TokenLength: 1, TokenTTL: 1}}, nil)
	ott.On("Create", mock.Anything, mock.Anything).Return(nil, errors.New(""))
	ip.On("FindByTypeAndName", mock.Anything, mock.Anything, mock.Anything).Return(&models.AppIdentityProvider{})
	ui.On("Get", mock.Anything, mock.Anything, mock.Anything).Return(&models.UserIdentity{ID: "1"}, nil)
	r.On("ApplicationService").Return(app)
	r.On("OneTimeTokenService").Return(ott)

	m := &ChangePasswordManager{
		r:                       r,
		userIdentityService:     ui,
		identityProviderService: ip,
	}
	err := m.ChangePasswordStart(&models.ChangePasswordStartForm{ClientID: bson.NewObjectId().Hex()})
	assert.NotNil(t, err)
	assert.Equal(t, "common", err.Code)
	assert.Equal(t, models.ErrorUnableCreateOttSettings, err.Message)
}

func TestChangePasswordStartReturnErrorOnSendMail(t *testing.T) {
	ip := &mocks.AppIdentityProviderServiceInterface{}
	ui := &mocks.UserIdentityServiceInterface{}
	app := &mocks.ApplicationServiceInterface{}
	ott := &mocks.OneTimeTokenServiceInterface{}
	mailer := &mocks.MailerInterface{}
	r := &mocks.InternalRegistry{}

	app.On("Get", mock.Anything).Return(&models.Application{PasswordSettings: &models.PasswordSettings{TokenLength: 1, TokenTTL: 1}}, nil)
	ott.On("Create", mock.Anything, mock.Anything).Return(&models.OneTimeToken{}, nil)
	mailer.On("Send", mock.Anything, mock.Anything, mock.Anything).Return(errors.New(""))
	ip.On("FindByTypeAndName", mock.Anything, mock.Anything, mock.Anything).Return(&models.AppIdentityProvider{})
	ui.On("Get", mock.Anything, mock.Anything, mock.Anything).Return(&models.UserIdentity{ID: "1"}, nil)
	r.On("ApplicationService").Return(app)
	r.On("OneTimeTokenService").Return(ott)
	r.On("Mailer").Return(mailer)

	m := &ChangePasswordManager{
		r:                       r,
		userIdentityService:     ui,
		identityProviderService: ip,
		TplCfg: &config.MailTemplates{
			ChangePasswordTpl: "./public/templates/email/change_password.html",
		},
	}
	err := m.ChangePasswordStart(&models.ChangePasswordStartForm{ClientID: bson.NewObjectId().Hex()})
	assert.NotNil(t, err)
	assert.Equal(t, "common", err.Code)
	assert.Equal(t, models.ErrorUnknownError, err.Message)
}

func TestChangePasswordStartReturnNilOnSuccessResult(t *testing.T) {
	ip := &mocks.AppIdentityProviderServiceInterface{}
	ui := &mocks.UserIdentityServiceInterface{}
	app := &mocks.ApplicationServiceInterface{}
	ott := &mocks.OneTimeTokenServiceInterface{}
	mailer := &mocks.MailerInterface{}
	r := &mocks.InternalRegistry{}

	app.On("Get", mock.Anything).Return(&models.Application{PasswordSettings: &models.PasswordSettings{TokenLength: 1, TokenTTL: 1}}, nil)
	ott.On("Create", mock.Anything, mock.Anything).Return(&models.OneTimeToken{}, nil)
	mailer.On("Send", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	ip.On("FindByTypeAndName", mock.Anything, mock.Anything, mock.Anything).Return(&models.AppIdentityProvider{})
	ui.On("Get", mock.Anything, mock.Anything, mock.Anything).Return(&models.UserIdentity{ID: "1"}, nil)
	r.On("ApplicationService").Return(app)
	r.On("OneTimeTokenService").Return(ott)
	r.On("Mailer").Return(mailer)

	m := &ChangePasswordManager{
		r:                       r,
		userIdentityService:     ui,
		identityProviderService: ip,
		TplCfg: &config.MailTemplates{
			ChangePasswordTpl: "./public/templates/email/change_password.html",
		},
	}
	err := m.ChangePasswordStart(&models.ChangePasswordStartForm{ClientID: bson.NewObjectId().Hex()})
	assert.Nil(t, err)
}

func TestChangePasswordVerifyReturnErrorOnDifferentPasswordAndRepeated(t *testing.T) {
	ip := &mocks.AppIdentityProviderServiceInterface{}
	ui := &mocks.UserIdentityServiceInterface{}
	r := &mocks.InternalRegistry{}

	m := &ChangePasswordManager{
		r:                       r,
		userIdentityService:     ui,
		identityProviderService: ip,
	}
	err := m.ChangePasswordVerify(&models.ChangePasswordVerifyForm{Password: "1", PasswordRepeat: "2"})
	assert.NotNil(t, err)
	assert.Equal(t, "password_repeat", err.Code)
	assert.Equal(t, models.ErrorPasswordRepeat, err.Message)
}

func TestChangePasswordVerifyReturnErrorWithIncorrectClient(t *testing.T) {
	ui := &mocks.UserIdentityServiceInterface{}
	app := &mocks.ApplicationServiceInterface{}
	r := &mocks.InternalRegistry{}

	ott := &mocks.OneTimeTokenServiceInterface{}
	ott.On("Use", mock.Anything, mock.MatchedBy(
		func(ts *models.ChangePasswordTokenSource) bool {
			ts.ClientID = bson.NewObjectId().Hex()
			return true
		})).Return(nil)

	app.On("Get", mock.Anything).Return(nil, errors.New(""))
	r.On("OneTimeTokenService").Return(ott)
	r.On("ApplicationService").Return(app)

	m := &ChangePasswordManager{
		r:                   r,
		userIdentityService: ui,
	}
	err := m.ChangePasswordVerify(&models.ChangePasswordVerifyForm{ClientID: bson.NewObjectId().Hex()})
	assert.NotNil(t, err)
	assert.Equal(t, "client_id", err.Code)
	assert.Equal(t, models.ErrorClientIdIncorrect, err.Message)
}

func TestChangePasswordVerifyReturnErrorWithInvalidPassword(t *testing.T) {
	ip := &mocks.AppIdentityProviderServiceInterface{}
	ui := &mocks.UserIdentityServiceInterface{}
	app := &mocks.ApplicationServiceInterface{}
	r := &mocks.InternalRegistry{}

	ott := &mocks.OneTimeTokenServiceInterface{}
	ott.On("Use", mock.Anything, mock.MatchedBy(
		func(ts *models.ChangePasswordTokenSource) bool {
			ts.ClientID = bson.NewObjectId().Hex()
			return true
		})).Return(nil)

	passSettings := &models.PasswordSettings{Min: 4, Max: 8, RequireSpecial: false, RequireUpper: false, RequireNumber: false}
	app.On("Get", mock.Anything).Return(&models.Application{PasswordSettings: passSettings}, nil)
	r.On("OneTimeTokenService").Return(ott)
	r.On("ApplicationService").Return(app)

	m := &ChangePasswordManager{
		r:                       r,
		userIdentityService:     ui,
		identityProviderService: ip,
	}
	err := m.ChangePasswordVerify(&models.ChangePasswordVerifyForm{ClientID: bson.NewObjectId().Hex()})
	assert.NotNil(t, err)
	assert.Equal(t, "password", err.Code)
	assert.Equal(t, models.ErrorPasswordIncorrect, err.Message)
}

func TestChangePasswordVerifyReturnErrorWithUseToken(t *testing.T) {
	ip := &mocks.AppIdentityProviderServiceInterface{}
	ui := &mocks.UserIdentityServiceInterface{}
	app := &mocks.ApplicationServiceInterface{}
	ott := &mocks.OneTimeTokenServiceInterface{}
	r := &mocks.InternalRegistry{}

	passSettings := &models.PasswordSettings{Min: 1, Max: 8, RequireSpecial: false, RequireUpper: false, RequireNumber: false}
	app.On("Get", mock.Anything).Return(&models.Application{PasswordSettings: passSettings}, nil)
	ott.On("Use", mock.Anything, mock.Anything).Return(errors.New(""))
	r.On("ApplicationService").Return(app)
	r.On("OneTimeTokenService").Return(ott)

	m := &ChangePasswordManager{
		r:                       r,
		userIdentityService:     ui,
		identityProviderService: ip,
	}
	err := m.ChangePasswordVerify(&models.ChangePasswordVerifyForm{Password: "1", PasswordRepeat: "1", ClientID: bson.NewObjectId().Hex()})
	assert.NotNil(t, err)
	assert.Equal(t, "common", err.Code)
	assert.Equal(t, models.ErrorCannotUseToken, err.Message)
}

func TestChangePasswordVerifyReturnErrorWithUnavailableIdentityProvider(t *testing.T) {
	ip := &mocks.AppIdentityProviderServiceInterface{}
	ui := &mocks.UserIdentityServiceInterface{}
	app := &mocks.ApplicationServiceInterface{}
	ott := &mocks.OneTimeTokenServiceInterface{}
	r := &mocks.InternalRegistry{}

	passSettings := &models.PasswordSettings{Min: 1, Max: 8, RequireSpecial: false, RequireUpper: false, RequireNumber: false}
	app.On("Get", mock.Anything).Return(&models.Application{PasswordSettings: passSettings}, nil)
	ott.On("Use", mock.Anything, mock.MatchedBy(
		func(ts *models.ChangePasswordTokenSource) bool {
			ts.ClientID = bson.NewObjectId().Hex()
			return true
		})).Return(nil)
	ip.On("FindByTypeAndName", mock.Anything, models.AppIdentityProviderTypePassword, models.AppIdentityProviderNameDefault).Return(nil)
	r.On("ApplicationService").Return(app)
	r.On("OneTimeTokenService").Return(ott)

	m := &ChangePasswordManager{
		r:                       r,
		userIdentityService:     ui,
		identityProviderService: ip,
	}
	err := m.ChangePasswordVerify(&models.ChangePasswordVerifyForm{Password: "1", PasswordRepeat: "1", ClientID: bson.NewObjectId().Hex()})
	assert.NotNil(t, err)
	assert.Equal(t, "common", err.Code)
	assert.Equal(t, models.ErrorUnknownError, err.Message)
}

func TestChangePasswordVerifyReturnErrorWithUnableToGetUserIdentity(t *testing.T) {
	ip := &mocks.AppIdentityProviderServiceInterface{}
	ui := &mocks.UserIdentityServiceInterface{}
	app := &mocks.ApplicationServiceInterface{}
	ott := &mocks.OneTimeTokenServiceInterface{}
	r := &mocks.InternalRegistry{}

	passSettings := &models.PasswordSettings{Min: 1, Max: 8, RequireSpecial: false, RequireUpper: false, RequireNumber: false}
	app.On("Get", mock.Anything).Return(&models.Application{PasswordSettings: passSettings}, nil)
	ott.On("Use", mock.Anything, mock.MatchedBy(
		func(ts *models.ChangePasswordTokenSource) bool {
			ts.ClientID = bson.NewObjectId().Hex()
			return true
		})).Return(nil)
	ip.On("FindByTypeAndName", mock.Anything, models.AppIdentityProviderTypePassword, models.AppIdentityProviderNameDefault).Return(&models.AppIdentityProvider{})
	ui.On("Get", mock.Anything, mock.Anything, mock.Anything).Return(&models.UserIdentity{}, nil)
	r.On("ApplicationService").Return(app)
	r.On("OneTimeTokenService").Return(ott)

	m := &ChangePasswordManager{
		r:                       r,
		userIdentityService:     ui,
		identityProviderService: ip,
	}
	err := m.ChangePasswordVerify(&models.ChangePasswordVerifyForm{Password: "1", PasswordRepeat: "1", ClientID: bson.NewObjectId().Hex()})
	assert.NotNil(t, err)
	assert.Equal(t, "common", err.Code)
	assert.Equal(t, models.ErrorUnknownError, err.Message)
}

func TestChangePasswordVerifyReturnErrorWithErrorOnGetUserIdentity(t *testing.T) {
	ip := &mocks.AppIdentityProviderServiceInterface{}
	ui := &mocks.UserIdentityServiceInterface{}
	app := &mocks.ApplicationServiceInterface{}
	ott := &mocks.OneTimeTokenServiceInterface{}
	r := &mocks.InternalRegistry{}

	passSettings := &models.PasswordSettings{Min: 1, Max: 8, RequireSpecial: false, RequireUpper: false, RequireNumber: false}
	app.On("Get", mock.Anything).Return(&models.Application{PasswordSettings: passSettings}, nil)
	ott.On("Use", mock.Anything, mock.MatchedBy(
		func(ts *models.ChangePasswordTokenSource) bool {
			ts.ClientID = bson.NewObjectId().Hex()
			return true
		})).Return(nil)
	ip.On("FindByTypeAndName", mock.Anything, models.AppIdentityProviderTypePassword, models.AppIdentityProviderNameDefault).Return(&models.AppIdentityProvider{})
	ui.On("Get", mock.Anything, mock.Anything, mock.Anything).Return(nil, errors.New(""))
	r.On("ApplicationService").Return(app)
	r.On("OneTimeTokenService").Return(ott)

	m := &ChangePasswordManager{
		r:                       r,
		userIdentityService:     ui,
		identityProviderService: ip,
	}
	err := m.ChangePasswordVerify(&models.ChangePasswordVerifyForm{Password: "1", PasswordRepeat: "1", ClientID: bson.NewObjectId().Hex()})
	assert.NotNil(t, err)
	assert.Equal(t, "common", err.Code)
	assert.Equal(t, models.ErrorUnknownError, err.Message)
}

func TestChangePasswordVerifyReturnErrorWithUnableToEncryptPassword(t *testing.T) {
	ip := &mocks.AppIdentityProviderServiceInterface{}
	ui := &mocks.UserIdentityServiceInterface{}
	app := &mocks.ApplicationServiceInterface{}
	ott := &mocks.OneTimeTokenServiceInterface{}
	r := &mocks.InternalRegistry{}

	passSettings := &models.PasswordSettings{Min: 1, Max: 8, RequireSpecial: false, RequireUpper: false, RequireNumber: false, BcryptCost: 32}
	app.On("Get", mock.Anything).Return(&models.Application{PasswordSettings: passSettings}, nil)
	ott.On("Use", mock.Anything, mock.MatchedBy(
		func(ts *models.ChangePasswordTokenSource) bool {
			ts.ClientID = bson.NewObjectId().Hex()
			return true
		})).Return(nil)
	ip.On("FindByTypeAndName", mock.Anything, models.AppIdentityProviderTypePassword, models.AppIdentityProviderNameDefault).Return(&models.AppIdentityProvider{})
	ui.On("Get", mock.Anything, mock.Anything, mock.Anything).Return(&models.UserIdentity{ID: bson.NewObjectId()}, nil)
	r.On("ApplicationService").Return(app)
	r.On("OneTimeTokenService").Return(ott)

	m := &ChangePasswordManager{
		r:                       r,
		userIdentityService:     ui,
		identityProviderService: ip,
	}
	err := m.ChangePasswordVerify(&models.ChangePasswordVerifyForm{Password: "1", PasswordRepeat: "1", ClientID: bson.NewObjectId().Hex()})
	assert.NotNil(t, err)
	assert.Equal(t, "password", err.Code)
	assert.Equal(t, models.ErrorCryptPassword, err.Message)
}

func TestChangePasswordVerifyReturnErrorWithUnableToUpdatePassword(t *testing.T) {
	ip := &mocks.AppIdentityProviderServiceInterface{}
	ui := &mocks.UserIdentityServiceInterface{}
	app := &mocks.ApplicationServiceInterface{}
	ott := &mocks.OneTimeTokenServiceInterface{}
	r := &mocks.InternalRegistry{}

	passSettings := &models.PasswordSettings{Min: 1, Max: 8, RequireSpecial: false, RequireUpper: false, RequireNumber: false, BcryptCost: 4}
	app.On("Get", mock.Anything).Return(&models.Application{PasswordSettings: passSettings}, nil)
	ott.On("Use", mock.Anything, mock.MatchedBy(
		func(ts *models.ChangePasswordTokenSource) bool {
			ts.ClientID = bson.NewObjectId().Hex()
			return true
		})).Return(nil)
	ip.On("FindByTypeAndName", mock.Anything, models.AppIdentityProviderTypePassword, models.AppIdentityProviderNameDefault).Return(&models.AppIdentityProvider{})
	ui.On("Get", mock.Anything, mock.Anything, mock.Anything).Return(&models.UserIdentity{ID: bson.NewObjectId()}, nil)
	ui.On("Update", mock.Anything).Return(errors.New(""))
	r.On("ApplicationService").Return(app)
	r.On("OneTimeTokenService").Return(ott)

	m := &ChangePasswordManager{
		r:                       r,
		userIdentityService:     ui,
		identityProviderService: ip,
	}
	err := m.ChangePasswordVerify(&models.ChangePasswordVerifyForm{Password: "1", PasswordRepeat: "1", ClientID: bson.NewObjectId().Hex()})
	assert.NotNil(t, err)
	assert.Equal(t, "password", err.Code)
	assert.Equal(t, models.ErrorUnableChangePassword, err.Message)
}

func TestChangePasswordVerifyReturnNilOnSuccessResult(t *testing.T) {
	ip := &mocks.AppIdentityProviderServiceInterface{}
	ui := &mocks.UserIdentityServiceInterface{}
	app := &mocks.ApplicationServiceInterface{}
	ott := &mocks.OneTimeTokenServiceInterface{}
	r := &mocks.InternalRegistry{}

	passSettings := &models.PasswordSettings{Min: 1, Max: 8, RequireSpecial: false, RequireUpper: false, RequireNumber: false, BcryptCost: 4}
	app.On("Get", mock.Anything).Return(&models.Application{PasswordSettings: passSettings}, nil)
	ott.On("Use", mock.Anything, mock.MatchedBy(
		func(ts *models.ChangePasswordTokenSource) bool {
			ts.ClientID = bson.NewObjectId().Hex()
			return true
		})).Return(nil)
	ip.On("FindByTypeAndName", mock.Anything, models.AppIdentityProviderTypePassword, models.AppIdentityProviderNameDefault).Return(&models.AppIdentityProvider{})
	ui.On("Get", mock.Anything, mock.Anything, mock.Anything).Return(&models.UserIdentity{ID: bson.NewObjectId()}, nil)
	ui.On("Update", mock.Anything).Return(nil)
	r.On("ApplicationService").Return(app)
	r.On("OneTimeTokenService").Return(ott)

	m := &ChangePasswordManager{
		r:                       r,
		userIdentityService:     ui,
		identityProviderService: ip,
	}
	err := m.ChangePasswordVerify(&models.ChangePasswordVerifyForm{Password: "1", PasswordRepeat: "1", ClientID: bson.NewObjectId().Hex()})
	assert.Nil(t, err)
}
