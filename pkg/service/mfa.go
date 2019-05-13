package service

import (
	"context"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/database"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/models"
	mfa "github.com/ProtocolONE/mfa-service/pkg/proto"
	"github.com/globalsign/mgo"
	"github.com/globalsign/mgo/bson"
	"github.com/micro/go-micro/client"
)

// MfaServiceInterface describes of methods for the mfa service.
type MfaServiceInterface interface {
	// Add adds a new MFA provider for the application.
	Add(*models.MfaProvider) error

	// List returns a list of available mfa providers for the application.
	List(bson.ObjectId) ([]*models.MfaProvider, error)

	// // Get return the mfa providers by id.
	Get(bson.ObjectId) (*models.MfaProvider, error)

	// AddUserProvider adds mfa provider for the user.
	AddUserProvider(*models.MfaUserProvider) error

	// GetUserProviders returns a list of available mfa providers for the user.
	GetUserProviders(*models.User) ([]*models.MfaProvider, error)
}

// MfaApiInterface describes of methods for the mfa micro-service.
// See more on https://github.com/ProtocolONE/mfa-service.
type MfaApiInterface interface {
	Create(ctx context.Context, in *mfa.MfaCreateDataRequest, opts ...client.CallOption) (*mfa.MfaCreateDataResponse, error)
	Check(ctx context.Context, in *mfa.MfaCheckDataRequest, opts ...client.CallOption) (*mfa.MfaCheckDataResponse, error)
}

// MfaService is the mfa service.
type MfaService struct {
	db *mgo.Database
}

// NewMfaService return new mfa service.
func NewMfaService(dbHandler database.MgoSession) *MfaService {
	return &MfaService{db: dbHandler.DB("")}
}

func (s MfaService) Add(provider *models.MfaProvider) error {
	if err := s.db.C(database.TableApplicationMfa).Insert(provider); err != nil {
		return err
	}

	return nil
}

func (s *MfaService) List(appId bson.ObjectId) (providers []*models.MfaProvider, err error) {
	if err = s.db.C(database.TableApplicationMfa).
		Find(nil).
		Select(bson.M{"app_id": appId}).
		All(&providers); err != nil {
		return nil, err
	}

	return providers, nil
}

func (s *MfaService) Get(id bson.ObjectId) (provider *models.MfaProvider, err error) {
	if err := s.db.C(database.TableApplicationMfa).
		FindId(id).
		One(&provider); err != nil {
		return nil, err
	}

	return provider, nil
}

func (s *MfaService) AddUserProvider(up *models.MfaUserProvider) error {
	if err := s.db.C(database.TableUserMfa).Insert(up); err != nil {
		return err
	}

	return nil
}

func (s *MfaService) GetUserProviders(u *models.User) (providers []*models.MfaProvider, err error) {
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
		var t = &models.MfaProvider{
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
