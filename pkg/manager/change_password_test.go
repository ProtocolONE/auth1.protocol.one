package manager

import (
	"testing"

	"github.com/ProtocolONE/auth1.protocol.one/internal/domain/entity"
	"github.com/ProtocolONE/auth1.protocol.one/internal/domain/repository"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/config"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/mocks"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/models"
	"github.com/globalsign/mgo/bson"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type changePasswordTest struct {
	ui     *mocks.UserIdentityServiceInterface
	app    *mocks.ApplicationServiceInterface
	ott    *mocks.OneTimeTokenServiceInterface
	mailer *mocks.MailerInterface
	r      *mocks.InternalRegistry
	m      *ChangePasswordManager

	space *entity.Space
}

func newChangePasswordTest() *changePasswordTest {
	return &changePasswordTest{
		ui:     &mocks.UserIdentityServiceInterface{},
		app:    &mocks.ApplicationServiceInterface{},
		ott:    &mocks.OneTimeTokenServiceInterface{},
		mailer: &mocks.MailerInterface{},
		r:      &mocks.InternalRegistry{},
		space: &entity.Space{
			PasswordSettings: entity.PasswordSettings{Min: 1, Max: 8, BcryptCost: 4},
			IdentityProviders: entity.IdentityProviders{{
				ID:          entity.IdentityProviderID(bson.NewObjectId().Hex()),
				Type:        entity.IDProviderTypePassword,
				Name:        entity.IDProviderNameDefault,
				DisplayName: "Initial connection",
			}},
		},
	}

}

func (test *changePasswordTest) init() {
	test.app.On("Get", mock.Anything).Return(&models.Application{}, nil)
	test.ott.On("Create", mock.Anything, mock.Anything).Return(&models.OneTimeToken{}, nil)
	test.mailer.On("Send", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	test.ui.On("Get", mock.Anything, mock.Anything, mock.Anything).Return(&models.UserIdentity{ID: bson.NewObjectId()}, nil)
	test.ui.On("Update", mock.Anything).Return(nil)
	test.r.On("ApplicationService").Return(test.app)
	test.r.On("OneTimeTokenService").Return(test.ott)
	test.r.On("Mailer").Return(test.mailer)
	test.r.On("Spaces").Return(repository.OneSpaceRepo(test.space))

	test.ott.On("Use", mock.Anything, mock.MatchedBy(
		func(ts *models.ChangePasswordTokenSource) bool {
			ts.ClientID = bson.NewObjectId().Hex()
			return true
		})).Return(nil)

	test.m = &ChangePasswordManager{
		r:                   test.r,
		userIdentityService: test.ui,
		TplCfg: &config.MailTemplates{
			ChangePasswordTpl: "./public/templates/email/change_password.html",
		},
	}
}

func TestChangePasswordStartReturnNilOnSuccessResult(t *testing.T) {
	test := newChangePasswordTest()
	test.init()

	err := test.m.ChangePasswordStart(&models.ChangePasswordStartForm{ClientID: bson.NewObjectId().Hex()})
	assert.Nil(t, err)
}

func TestChangePasswordVerifyReturnNilOnSuccessResult(t *testing.T) {
	test := newChangePasswordTest()
	test.init()

	err := test.m.ChangePasswordVerify(&models.ChangePasswordVerifyForm{Password: "1", PasswordRepeat: "1", ClientID: bson.NewObjectId().Hex()})
	assert.Nil(t, err)
}

///////////////////////////////////////////////////////////////////////
// Start Negative cases

func TestChangePasswordStartReturnErrorWithIncorrectClient(t *testing.T) {
	test := newChangePasswordTest()
	test.app.On("Get", mock.Anything).Return(nil, errors.New(""))
	test.init()

	err := test.m.ChangePasswordStart(&models.ChangePasswordStartForm{ClientID: bson.NewObjectId().Hex()})
	if assert.NotNil(t, err) {
		assert.Equal(t, "client_id", err.Code)
		assert.Equal(t, models.ErrorClientIdIncorrect, err.Message)
	}
}

func TestChangePasswordStartReturnErrorWithErrorOnUserIdentity(t *testing.T) {
	test := newChangePasswordTest()
	test.ui.On("Get", mock.Anything, mock.Anything, mock.Anything).Return(nil, errors.New(""))
	test.init()

	err := test.m.ChangePasswordStart(&models.ChangePasswordStartForm{ClientID: bson.NewObjectId().Hex()})
	if assert.NotNil(t, err) {
		assert.Equal(t, "email", err.Code)
		assert.Equal(t, models.ErrorUnknownError, err.Message)
	}
}

func TestChangePasswordStartReturnNilIfUserNotFound(t *testing.T) {
	test := newChangePasswordTest()
	test.ui.On("Get", mock.Anything, mock.Anything, mock.Anything).Return(&models.UserIdentity{}, nil)
	test.init()

	err := test.m.ChangePasswordStart(&models.ChangePasswordStartForm{ClientID: bson.NewObjectId().Hex()})
	assert.Nil(t, err)
}

func TestChangePasswordStartReturnErrorOnCreateToken(t *testing.T) {
	test := newChangePasswordTest()
	test.ott.On("Create", mock.Anything, mock.Anything).Return(nil, errors.New(""))
	test.init()

	err := test.m.ChangePasswordStart(&models.ChangePasswordStartForm{ClientID: bson.NewObjectId().Hex()})
	if assert.NotNil(t, err) {
		assert.Equal(t, "common", err.Code)
		assert.Equal(t, models.ErrorUnableCreateOttSettings, err.Message)
	}
}

func TestChangePasswordStartReturnErrorOnSendMail(t *testing.T) {
	test := newChangePasswordTest()
	test.mailer.On("Send", mock.Anything, mock.Anything, mock.Anything).Return(errors.New(""))
	test.init()

	err := test.m.ChangePasswordStart(&models.ChangePasswordStartForm{ClientID: bson.NewObjectId().Hex()})
	if assert.NotNil(t, err) {
		assert.Equal(t, "common", err.Code)
		assert.Equal(t, models.ErrorUnknownError, err.Message)
	}
}

///////////////////////////////////////////////////////////////////////
// Verify Negative cases

func TestChangePasswordVerifyReturnErrorOnDifferentPasswordAndRepeated(t *testing.T) {
	test := newChangePasswordTest()
	test.init()

	err := test.m.ChangePasswordVerify(&models.ChangePasswordVerifyForm{Password: "1", PasswordRepeat: "2"})
	if assert.NotNil(t, err) {
		assert.Equal(t, "password_repeat", err.Code)
		assert.Equal(t, models.ErrorPasswordRepeat, err.Message)
	}
}

func TestChangePasswordVerifyReturnErrorWithIncorrectClient(t *testing.T) {
	test := newChangePasswordTest()
	test.app.On("Get", mock.Anything).Return(nil, errors.New(""))
	test.init()

	err := test.m.ChangePasswordVerify(&models.ChangePasswordVerifyForm{ClientID: bson.NewObjectId().Hex()})
	if assert.NotNil(t, err) {
		assert.Equal(t, "client_id", err.Code)
		assert.Equal(t, models.ErrorClientIdIncorrect, err.Message)
	}
}

func TestChangePasswordVerifyReturnErrorWithInvalidPassword(t *testing.T) {
	test := newChangePasswordTest()
	test.init()

	err := test.m.ChangePasswordVerify(&models.ChangePasswordVerifyForm{ClientID: bson.NewObjectId().Hex()})
	if assert.NotNil(t, err) {
		assert.Equal(t, "password", err.Code)
		assert.Equal(t, models.ErrorPasswordIncorrect, err.Message)
	}
}

func TestChangePasswordVerifyReturnErrorWithUseToken(t *testing.T) {
	test := newChangePasswordTest()
	test.ott.On("Use", mock.Anything, mock.Anything).Return(errors.New(""))
	test.init()

	err := test.m.ChangePasswordVerify(&models.ChangePasswordVerifyForm{Password: "1", PasswordRepeat: "1", ClientID: bson.NewObjectId().Hex()})
	if assert.NotNil(t, err) {
		assert.Equal(t, "common", err.Code)
		assert.Equal(t, models.ErrorCannotUseToken, err.Message)
	}
}

func TestChangePasswordVerifyReturnErrorWithUnableToGetUserIdentity(t *testing.T) {
	test := newChangePasswordTest()
	test.ui.On("Get", mock.Anything, mock.Anything, mock.Anything).Return(&models.UserIdentity{}, nil)
	test.init()

	err := test.m.ChangePasswordVerify(&models.ChangePasswordVerifyForm{Password: "1", PasswordRepeat: "1", ClientID: bson.NewObjectId().Hex()})
	if assert.NotNil(t, err) {
		assert.Equal(t, "common", err.Code)
		assert.Equal(t, models.ErrorUnknownError, err.Message)
	}
}

func TestChangePasswordVerifyReturnErrorWithErrorOnGetUserIdentity(t *testing.T) {
	test := newChangePasswordTest()
	test.ui.On("Get", mock.Anything, mock.Anything, mock.Anything).Return(nil, errors.New(""))
	test.init()

	err := test.m.ChangePasswordVerify(&models.ChangePasswordVerifyForm{Password: "1", PasswordRepeat: "1", ClientID: bson.NewObjectId().Hex()})
	if assert.NotNil(t, err) {
		assert.Equal(t, "common", err.Code)
		assert.Equal(t, models.ErrorUnknownError, err.Message)
	}
}

func TestChangePasswordVerifyReturnErrorWithUnableToEncryptPassword(t *testing.T) {
	test := newChangePasswordTest()
	test.space.PasswordSettings.BcryptCost = 32
	test.init()

	err := test.m.ChangePasswordVerify(&models.ChangePasswordVerifyForm{Password: "1", PasswordRepeat: "1", ClientID: bson.NewObjectId().Hex()})
	if assert.NotNil(t, err) {
		assert.Equal(t, "password", err.Code)
		assert.Equal(t, models.ErrorCryptPassword, err.Message)
	}
}

func TestChangePasswordVerifyReturnErrorWithUnableToUpdatePassword(t *testing.T) {
	test := newChangePasswordTest()
	test.ui.On("Update", mock.Anything).Return(errors.New(""))
	test.init()

	err := test.m.ChangePasswordVerify(&models.ChangePasswordVerifyForm{Password: "1", PasswordRepeat: "1", ClientID: bson.NewObjectId().Hex()})
	if assert.NotNil(t, err) {
		assert.Equal(t, "password", err.Code)
		assert.Equal(t, models.ErrorUnableChangePassword, err.Message)
	}
}
