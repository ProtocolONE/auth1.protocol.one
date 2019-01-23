package models

import (
	"auth-one-api/pkg/database"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

type (
	MfaService struct {
		db *mgo.Database
	}

	MFARequiredError CommonError

	MfaAuthenticator struct {
		ID            bson.ObjectId `json:"id"`
		Secret        string        `json:"secret"`
		ObbChannel    string        `json:"oob_channel,omitempty"`
		BarcodeUri    string        `json:"barcode_uri,omitempty"`
		Type          string        `json:"authenticator_type"`
		RecoveryCodes []string      `json:"recovery_codes"`
	}

	MfaChallengeForm struct {
		ClientId   string `json:"client_id" form:"client_id" validate:"required"`
		Connection string `json:"connection" form:"connection" validate:"required"`
		Token      string `json:"mfa_token" form:"mfa_token" validate:"required"`
		Type       string `json:"challenge_type" form:"challenge_type"`
	}

	MfaVerifyForm struct {
		ClientId   string `json:"client_id" form:"client_id" validate:"required"`
		ProviderId string `json:"provider_id" form:"provider_id" validate:"required"`
		Token      string `json:"mfa_token" form:"mfa_token" validate:"required"`
		Code       string `json:"code" form:"code"`
	}

	MfaAddForm struct {
		ClientId    string `json:"client_id" form:"client_id" validate:"required"`
		ProviderId  string `json:"provider_id" form:"provider_id" validate:"required"`
		Code        string `json:"code" form:"code"`
		PhoneNumber string `json:"phone_number" form:"phone_number"`
	}

	MfaApplicationForm struct {
		AppId       bson.ObjectId               `json:"app_id" validate:"required"`
		MfaProvider *MfaApplicationProviderForm `json:"mfa_provider" validate:"required"`
	}

	MfaApplicationProviderForm struct {
		Name    string `bson:"name" json:"name" validate:"required"`
		Channel string `bson:"channel" json:"channel"`
		Type    string `bson:"type" json:"type"`
	}

	MfaProvider struct {
		ID      bson.ObjectId `bson:"_id" json:"id"`
		AppID   bson.ObjectId `bson:"app_id" json:"app_id"`
		Name    string        `bson:"name" json:"name"`
		Type    string        `bson:"type" json:"type"`
		Channel string        `bson:"channel" json:"channel"`
	}

	MfaUserProvider struct {
		UserID     bson.ObjectId `bson:"user_id" json:"user_id"`
		ProviderID bson.ObjectId `bson:"provider_id" json:"provider_id"`
	}

	UserMfaToken struct {
		UserIdentity *UserIdentity
		MfaProvider  *MfaProvider
	}

	MfaConnection struct {
		Name    string `bson:"name" json:"name"`
		Type    string `bson:"type" json:"type"`
		Channel string `bson:"channel" json:"channel"`
	}
)

func (m MFARequiredError) Error() string {
	return m.Message
}

func (m *MFARequiredError) GetCode() string {
	return m.Code
}

func (m *MFARequiredError) GetMessage() string {
	return m.Message
}

func NewMfaService(dbHandler *database.Handler) *MfaService {
	return &MfaService{dbHandler.Session.DB(dbHandler.Name)}
}

func (s MfaService) Add(provider *MfaProvider) error {
	if err := s.db.C(database.TableApplicationMfa).Insert(provider); err != nil {
		return err
	}

	return nil
}

func (s *MfaService) List(appId bson.ObjectId) (providers []*MfaProvider, err error) {
	if err = s.db.C(database.TableApplicationMfa).
		Find(nil).
		Select(bson.M{"app_id": appId}).
		All(&providers); err != nil {
		return nil, err
	}

	return providers, nil
}

func (s *MfaService) Get(id bson.ObjectId) (provider *MfaProvider, err error) {
	if err := s.db.C(database.TableApplicationMfa).
		FindId(id).
		One(&provider); err != nil {
		return nil, err
	}

	return provider, nil
}

func (s *MfaService) AddUserProvider(up *MfaUserProvider) error {
	if err := s.db.C(database.TableUserMfa).Insert(up); err != nil {
		return err
	}

	return nil
}

func (s *MfaService) GetUserProviders(u *User) (providers []*MfaProvider, err error) {
	collection := s.db.C(database.TableUserMfa)
	pipeline := []bson.M{
		{"$match": bson.M{"user_id": u.ID}},
		{"$lookup": bson.M{"from": database.TableApplicationMfa, "localField": "provider_id", "foreignField": "_id", "as": "results"}},
	}
	pipe := collection.Pipe(pipeline)
	iter := pipe.Iter()
	resp := bson.M{}

	for iter.Next(&resp) {
		result := resp["results"].([]interface{})[0].(bson.M)
		var t = &MfaProvider{
			ID:      result["_id"].(bson.ObjectId),
			AppID:   result["app_id"].(bson.ObjectId),
			Name:    result["name"].(string),
			Type:    result["type"].(string),
			Channel: result["channel"].(string),
		}
		providers = append(providers, t)
	}

	return providers, nil
}
