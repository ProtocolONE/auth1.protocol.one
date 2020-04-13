package manager

import (
	"testing"

	"github.com/ProtocolONE/auth1.protocol.one/pkg/mocks"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/models"
	"github.com/ProtocolONE/mfa-service/pkg/proto"
	"github.com/globalsign/mgo"
	"github.com/globalsign/mgo/bson"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestMFAManager(t *testing.T) {
	s := &mocks.MgoSession{}
	s.On("DB", mock.Anything).Return(&mgo.Database{})
	r := mockIntRegistry()
	m := NewMFAManager(s, r)
	assert.Implements(t, (*MFAManagerInterface)(nil), m)
}

func mockIntRegistry() *mocks.InternalRegistry {
	spaces := &mocks.SpaceServiceInterface{}
	spaces.On("GetSpace", mock.Anything).Return(&models.Space{}, nil)

	r := &mocks.InternalRegistry{}
	r.On("GeoIpService").Return(nil)
	r.On("SpaceService").Return(spaces)
	return r
}

func TestMFAVerifyReturnErrorWithUnableToGetToken(t *testing.T) {
	ott := &mocks.OneTimeTokenServiceInterface{}
	r := mockIntRegistry()

	ott.On("Get", mock.Anything, mock.Anything).Return(errors.New(""))
	r.On("OneTimeTokenService").Return(ott)

	m := &MFAManager{r: r}
	err := m.MFAVerify(getContext(), &models.MfaVerifyForm{})
	assert.NotNil(t, err)
	assert.Equal(t, "mfa_token", err.Code)
	assert.Equal(t, models.ErrorCannotUseToken, err.Message)
}

func TestMFAVerifyReturnErrorWithCheckCode(t *testing.T) {
	ott := &mocks.OneTimeTokenServiceInterface{}
	mfa := &mocks.MfaApiInterface{}
	r := mockIntRegistry()

	ott.On("Get", "token", &models.UserMfaToken{}).Return(nil).Run(func(args mock.Arguments) {
		arg := args.Get(1).(*models.UserMfaToken)
		arg.UserIdentity = &models.UserIdentity{UserID: bson.NewObjectId()}
		arg.MfaProvider = &models.MfaProvider{ID: bson.NewObjectId()}
	})
	mfa.On("Check", mock.Anything, mock.Anything).Return(nil, errors.New(""))
	r.On("OneTimeTokenService").Return(ott)
	r.On("MfaService").Return(mfa)

	m := &MFAManager{r: r}
	err := m.MFAVerify(getContext(), &models.MfaVerifyForm{Token: "token"})
	assert.NotNil(t, err)
	assert.Equal(t, "common", err.Code)
	assert.Equal(t, models.ErrorMfaCodeInvalid, err.Message)
}

func TestMFAVerifyReturnErrorWithResultIsFalse(t *testing.T) {
	ott := &mocks.OneTimeTokenServiceInterface{}
	mfa := &mocks.MfaApiInterface{}
	r := mockIntRegistry()

	ott.On("Get", "token", &models.UserMfaToken{}).Return(nil).Run(func(args mock.Arguments) {
		arg := args.Get(1).(*models.UserMfaToken)
		arg.UserIdentity = &models.UserIdentity{UserID: bson.NewObjectId()}
		arg.MfaProvider = &models.MfaProvider{ID: bson.NewObjectId()}
	})
	mfa.On("Check", mock.Anything, mock.Anything).Return(&proto.MfaCheckDataResponse{Result: false}, nil)
	r.On("OneTimeTokenService").Return(ott)
	r.On("MfaService").Return(mfa)

	m := &MFAManager{r: r}
	err := m.MFAVerify(getContext(), &models.MfaVerifyForm{Token: "token"})
	assert.NotNil(t, err)
	assert.Equal(t, "common", err.Code)
	assert.Equal(t, models.ErrorMfaCodeInvalid, err.Message)
}

func TestMFAVerifyReturnErrorWithUnableToGetUser(t *testing.T) {
	ott := &mocks.OneTimeTokenServiceInterface{}
	mfa := &mocks.MfaApiInterface{}
	us := &mocks.UserServiceInterface{}
	r := mockIntRegistry()

	ott.On("Get", "token", &models.UserMfaToken{}).Return(nil).Run(func(args mock.Arguments) {
		arg := args.Get(1).(*models.UserMfaToken)
		arg.UserIdentity = &models.UserIdentity{UserID: bson.NewObjectId()}
		arg.MfaProvider = &models.MfaProvider{ID: bson.NewObjectId()}
	})
	mfa.On("Check", mock.Anything, mock.Anything).Return(&proto.MfaCheckDataResponse{Result: true}, nil)
	us.On("Get", mock.Anything).Return(nil, errors.New(""))
	r.On("OneTimeTokenService").Return(ott)
	r.On("MfaService").Return(mfa)

	m := &MFAManager{
		r:           r,
		userService: us,
	}
	err := m.MFAVerify(getContext(), &models.MfaVerifyForm{Token: "token"})
	assert.NotNil(t, err)
	assert.Equal(t, "email", err.Code)
	assert.Equal(t, models.ErrorLoginIncorrect, err.Message)
}

func TestMFAVerifySuccessResult(t *testing.T) {
	ott := &mocks.OneTimeTokenServiceInterface{}
	mfa := &mocks.MfaApiInterface{}
	us := &mocks.UserServiceInterface{}
	a := &mocks.AuthLogServiceInterface{}
	r := mockIntRegistry()

	ott.On("Get", "token", &models.UserMfaToken{}).Return(nil).Run(func(args mock.Arguments) {
		arg := args.Get(1).(*models.UserMfaToken)
		arg.UserIdentity = &models.UserIdentity{UserID: bson.NewObjectId()}
		arg.MfaProvider = &models.MfaProvider{ID: bson.NewObjectId()}
	})
	mfa.On("Check", mock.Anything, mock.Anything).Return(&proto.MfaCheckDataResponse{Result: true}, nil)
	us.On("Get", mock.Anything).Return(&models.User{}, nil)
	a.On("Add", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	r.On("OneTimeTokenService").Return(ott)
	r.On("MfaService").Return(mfa)

	m := &MFAManager{
		r:              r,
		userService:    us,
		authLogService: a,
	}
	err := m.MFAVerify(getContext(), &models.MfaVerifyForm{Token: "token"})
	assert.Nil(t, err)
}

func TestMFAAddReturnErrorWithUnableToGetApplication(t *testing.T) {
	app := &mocks.ApplicationServiceInterface{}
	r := mockIntRegistry()

	app.On("Get", mock.Anything).Return(nil, errors.New(""))
	r.On("ApplicationService").Return(app)

	m := &MFAManager{
		r: r,
	}
	_, err := m.MFAAdd(getContext(), &models.MfaAddForm{ClientId: bson.NewObjectId().Hex()})
	assert.NotNil(t, err)
	assert.Equal(t, "client_id", err.Code)
	assert.Equal(t, models.ErrorClientIdIncorrect, err.Message)
}

func TestMFAAddReturnErrorWithUnableToGetProvider(t *testing.T) {
	app := &mocks.ApplicationServiceInterface{}
	mfa := &mocks.MfaServiceInterface{}
	r := mockIntRegistry()

	app.On("Get", mock.Anything).Return(&models.Application{}, nil)
	mfa.On("Get", mock.Anything).Return(nil, errors.New(""))
	r.On("ApplicationService").Return(app)

	m := &MFAManager{
		r:          r,
		mfaService: mfa,
	}
	_, err := m.MFAAdd(getContext(), &models.MfaAddForm{ClientId: bson.NewObjectId().Hex(), ProviderId: bson.NewObjectId().Hex()})
	assert.NotNil(t, err)
	assert.Equal(t, "provider_id", err.Code)
	assert.Equal(t, models.ErrorProviderIdIncorrect, err.Message)
}

func TestMFAAddReturnErrorWithUnableToGetProvider2(t *testing.T) {
	app := &mocks.ApplicationServiceInterface{}
	mfa := &mocks.MfaServiceInterface{}
	r := mockIntRegistry()

	app.On("Get", mock.Anything).Return(&models.Application{}, nil)
	mfa.On("Get", mock.Anything).Return(nil, nil)
	r.On("ApplicationService").Return(app)

	m := &MFAManager{
		r:          r,
		mfaService: mfa,
	}
	_, err := m.MFAAdd(getContext(), &models.MfaAddForm{ClientId: bson.NewObjectId().Hex(), ProviderId: bson.NewObjectId().Hex()})
	assert.NotNil(t, err)
	assert.Equal(t, "provider_id", err.Code)
	assert.Equal(t, models.ErrorProviderIdIncorrect, err.Message)
}

func TestMFAAddReturnErrorWithIncorrectAuthHeader(t *testing.T) {
	app := &mocks.ApplicationServiceInterface{}
	mfa := &mocks.MfaServiceInterface{}
	mfaApi := &mocks.MfaApiInterface{}
	r := mockIntRegistry()

	app.On("Get", mock.Anything).Return(&models.Application{}, nil)
	mfa.On("Get", mock.Anything).Return(&models.MfaProvider{ID: bson.NewObjectId()}, nil)
	mfaApi.On("Create", mock.Anything, mock.Anything).Return(nil, errors.New(""))
	r.On("ApplicationService").Return(app)
	r.On("MfaService").Return(mfaApi)

	m := &MFAManager{
		r:          r,
		mfaService: mfa,
	}
	_, err := m.MFAAdd(getContext(), &models.MfaAddForm{ClientId: bson.NewObjectId().Hex(), ProviderId: bson.NewObjectId().Hex()})
	assert.NotNil(t, err)
	assert.Equal(t, "client_id", err.Code)
	assert.Equal(t, models.ErrorClientIdIncorrect, err.Message)
}

func TestMFAAddReturnErrorWithUnableToCreateMfa(t *testing.T) {
	app := &mocks.ApplicationServiceInterface{}
	mfa := &mocks.MfaServiceInterface{}
	mfaApi := &mocks.MfaApiInterface{}
	r := mockIntRegistry()

	app.On("Get", mock.Anything).Return(&models.Application{}, nil)
	mfa.On("Get", mock.Anything).Return(&models.MfaProvider{ID: bson.NewObjectId()}, nil)
	mfaApi.On("Create", mock.Anything, mock.Anything).Return(nil, errors.New(""))
	r.On("ApplicationService").Return(app)
	r.On("MfaService").Return(mfaApi)

	m := &MFAManager{
		r:          r,
		mfaService: mfa,
	}

	headers := map[string]interface{}{"Authorization": "Bearer 123", "X-CLIENT-ID": bson.NewObjectId().Hex()}
	_, err := m.MFAAdd(getContext(map[string]interface{}{"headers": headers}), &models.MfaAddForm{ClientId: bson.NewObjectId().Hex(), ProviderId: bson.NewObjectId().Hex()})
	assert.NotNil(t, err)
	assert.Equal(t, "common", err.Code)
	assert.Equal(t, models.ErrorMfaClientAdd, err.Message)
}

func TestMFAAddReturnErrorWithUnableToAddProvider(t *testing.T) {
	app := &mocks.ApplicationServiceInterface{}
	mfa := &mocks.MfaServiceInterface{}
	mfaApi := &mocks.MfaApiInterface{}
	r := mockIntRegistry()

	app.On("Get", mock.Anything).Return(&models.Application{}, nil)
	mfa.On("Get", mock.Anything).Return(&models.MfaProvider{ID: bson.NewObjectId()}, nil)
	mfaApi.On("Create", mock.Anything, mock.Anything).Return(&proto.MfaCreateDataResponse{}, nil)
	mfa.On("AddUserProvider", mock.Anything).Return(errors.New(""))
	r.On("ApplicationService").Return(app)
	r.On("MfaService").Return(mfaApi)

	m := &MFAManager{
		r:          r,
		mfaService: mfa,
	}

	headers := map[string]interface{}{"Authorization": "Bearer 123", "X-CLIENT-ID": bson.NewObjectId().Hex()}
	_, err := m.MFAAdd(getContext(map[string]interface{}{"headers": headers}), &models.MfaAddForm{ClientId: bson.NewObjectId().Hex(), ProviderId: bson.NewObjectId().Hex()})
	assert.NotNil(t, err)
	assert.Equal(t, "common", err.Code)
	assert.Equal(t, models.ErrorMfaClientAdd, err.Message)
}

func TestMFAAddReturnSuccess(t *testing.T) {
	app := &mocks.ApplicationServiceInterface{}
	mfa := &mocks.MfaServiceInterface{}
	mfaApi := &mocks.MfaApiInterface{}
	r := mockIntRegistry()

	app.On("Get", mock.Anything).Return(&models.Application{}, nil)
	mfa.On("Get", mock.Anything).Return(&models.MfaProvider{ID: bson.NewObjectId()}, nil)
	mfaApi.On("Create", mock.Anything, mock.Anything).Return(&proto.MfaCreateDataResponse{}, nil)
	mfa.On("AddUserProvider", mock.Anything).Return(nil)
	r.On("ApplicationService").Return(app)
	r.On("MfaService").Return(mfaApi)

	m := &MFAManager{
		r:          r,
		mfaService: mfa,
	}

	headers := map[string]interface{}{"Authorization": "Bearer 123", "X-CLIENT-ID": bson.NewObjectId().Hex()}
	_, err := m.MFAAdd(getContext(map[string]interface{}{"headers": headers}), &models.MfaAddForm{ClientId: bson.NewObjectId().Hex(), ProviderId: bson.NewObjectId().Hex()})
	assert.Nil(t, err)
}

func TestMFAChallengeReturnNil(t *testing.T) {
	m := &MFAManager{}
	err := m.MFAChallenge(&models.MfaChallengeForm{})
	assert.Nil(t, err)
}

func TestMFAManagerError_MFAList(t *testing.T) {
	mfa := &mocks.MfaServiceInterface{}
	r := mockIntRegistry()

	mfa.On("GetUserProviders", mock.Anything).Return([]*models.MfaProvider{}, errors.New("Some error"))

	m := &MFAManager{
		r:          r,
		mfaService: mfa,
	}

	_, err := m.MFAList(getContext(), &models.MfaListForm{ClientId: bson.NewObjectId().Hex()})
	assert.NotNil(t, err)
	assert.Equal(t, "common", err.Code)
	assert.Equal(t, models.ErrorAppIdIncorrect, err.Message)
}

func TestMFAManagerSuccess_MFAList(t *testing.T) {
	mfa := &mocks.MfaServiceInterface{}
	r := mockIntRegistry()

	mfa.On("GetUserProviders", mock.Anything).Return([]*models.MfaProvider{}, nil)

	m := &MFAManager{
		r:          r,
		mfaService: mfa,
	}

	_, err := m.MFAList(getContext(), &models.MfaListForm{ClientId: bson.NewObjectId().Hex()})
	assert.Nil(t, err)
}

func TestMFAManagerProvidersMismatch_MFARemove(t *testing.T) {
	app := &mocks.ApplicationServiceInterface{}
	mfa := &mocks.MfaServiceInterface{}
	mfaApi := &mocks.MfaApiInterface{}
	r := mockIntRegistry()

	app.On("Get", mock.Anything).Return(&models.Application{ID: bson.NewObjectId()}, nil)
	mfa.On("Get", mock.Anything).Return(&models.MfaProvider{ID: bson.NewObjectId(), AppID: bson.NewObjectId()}, nil)
	mfa.On("RemoveUserProvider", mock.Anything).Return(nil)
	r.On("ApplicationService").Return(app)
	r.On("MfaService").Return(mfaApi)

	m := &MFAManager{
		r:          r,
		mfaService: mfa,
	}

	headers := map[string]interface{}{"Authorization": "Bearer 123", "X-CLIENT-ID": bson.NewObjectId().Hex()}
	err := m.MFARemove(getContext(map[string]interface{}{"headers": headers}), &models.MfaRemoveForm{ClientId: bson.NewObjectId().Hex(), ProviderId: bson.NewObjectId().Hex()})
	assert.NotNil(t, err)
	assert.Equal(t, "provider_id", err.Code)
	assert.Equal(t, models.ErrorProviderIdIncorrect, err.Message)
}

func TestMFAManagerAppIdIncorrect_MFARemove(t *testing.T) {
	app := &mocks.ApplicationServiceInterface{}
	mfa := &mocks.MfaServiceInterface{}
	mfaApi := &mocks.MfaApiInterface{}
	r := mockIntRegistry()

	app.On("Get", mock.Anything).Return(&models.Application{ID: bson.NewObjectId()}, errors.New("Some error"))
	mfa.On("Get", mock.Anything).Return(&models.MfaProvider{ID: bson.NewObjectId(), AppID: bson.NewObjectId()}, nil)
	mfa.On("RemoveUserProvider", mock.Anything).Return(nil)
	r.On("ApplicationService").Return(app)
	r.On("MfaService").Return(mfaApi)

	m := &MFAManager{
		r:          r,
		mfaService: mfa,
	}

	headers := map[string]interface{}{"Authorization": "Bearer 123", "X-CLIENT-ID": bson.NewObjectId().Hex()}
	err := m.MFARemove(getContext(map[string]interface{}{"headers": headers}), &models.MfaRemoveForm{ClientId: bson.NewObjectId().Hex(), ProviderId: bson.NewObjectId().Hex()})
	assert.NotNil(t, err)
	assert.Equal(t, "client_id", err.Code)
	assert.Equal(t, models.ErrorClientIdIncorrect, err.Message)
}

func TestMFAManagerErrorWithoutHeaders_MFARemove(t *testing.T) {
	app := &mocks.ApplicationServiceInterface{}
	mfa := &mocks.MfaServiceInterface{}
	mfaApi := &mocks.MfaApiInterface{}
	r := mockIntRegistry()

	id := bson.NewObjectId()
	app.On("Get", mock.Anything).Return(&models.Application{ID: id}, nil)
	mfa.On("Get", mock.Anything).Return(&models.MfaProvider{ID: bson.NewObjectId(), AppID: id}, nil)
	mfa.On("RemoveUserProvider", mock.Anything).Return(nil)
	r.On("ApplicationService").Return(app)
	r.On("MfaService").Return(mfaApi)

	m := &MFAManager{
		r:          r,
		mfaService: mfa,
	}

	err := m.MFARemove(getContext(), &models.MfaRemoveForm{ClientId: bson.NewObjectId().Hex(), ProviderId: bson.NewObjectId().Hex()})
	assert.NotNil(t, err)
	assert.Equal(t, "client_id", err.Code)
	assert.Equal(t, models.ErrorClientIdIncorrect, err.Message)
}

func TestMFAManagerError_MFARemove(t *testing.T) {
	app := &mocks.ApplicationServiceInterface{}
	mfa := &mocks.MfaServiceInterface{}
	mfaApi := &mocks.MfaApiInterface{}
	r := mockIntRegistry()

	id := bson.NewObjectId()
	app.On("Get", mock.Anything).Return(&models.Application{ID: id}, nil)
	mfa.On("Get", mock.Anything).Return(&models.MfaProvider{ID: bson.NewObjectId(), AppID: id}, nil)
	mfa.On("RemoveUserProvider", mock.Anything).Return(errors.New("Some error"))
	r.On("ApplicationService").Return(app)
	r.On("MfaService").Return(mfaApi)

	m := &MFAManager{
		r:          r,
		mfaService: mfa,
	}

	headers := map[string]interface{}{"Authorization": "Bearer 123", "X-CLIENT-ID": bson.NewObjectId().Hex()}
	err := m.MFARemove(getContext(map[string]interface{}{"headers": headers}), &models.MfaRemoveForm{ClientId: bson.NewObjectId().Hex(), ProviderId: bson.NewObjectId().Hex()})
	assert.NotNil(t, err)
	assert.Equal(t, "common", err.Code)
	assert.Equal(t, models.ErrorMfaClientRemove, err.Message)
}

func TestMFAManagerSuccess_MFARemove(t *testing.T) {
	app := &mocks.ApplicationServiceInterface{}
	mfa := &mocks.MfaServiceInterface{}
	mfaApi := &mocks.MfaApiInterface{}
	r := mockIntRegistry()

	id := bson.NewObjectId()
	app.On("Get", mock.Anything).Return(&models.Application{ID: id}, nil)
	mfa.On("Get", mock.Anything).Return(&models.MfaProvider{ID: bson.NewObjectId(), AppID: id}, nil)
	mfa.On("RemoveUserProvider", mock.Anything).Return(nil)
	r.On("ApplicationService").Return(app)
	r.On("MfaService").Return(mfaApi)

	m := &MFAManager{
		r:          r,
		mfaService: mfa,
	}

	headers := map[string]interface{}{"Authorization": "Bearer 123", "X-CLIENT-ID": bson.NewObjectId().Hex()}
	err := m.MFARemove(getContext(map[string]interface{}{"headers": headers}), &models.MfaRemoveForm{ClientId: bson.NewObjectId().Hex(), ProviderId: bson.NewObjectId().Hex()})
	assert.Nil(t, err)
}
