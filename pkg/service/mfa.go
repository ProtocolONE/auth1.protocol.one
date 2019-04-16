package service

import (
	"github.com/ProtocolONE/auth1.protocol.one/pkg/database"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/models"
	"github.com/globalsign/mgo"
	"github.com/globalsign/mgo/bson"
)

type MfaServiceInterface interface {
	Add(*models.MfaProvider) error
	List(bson.ObjectId) ([]*models.MfaProvider, error)
	Get(bson.ObjectId) (*models.MfaProvider, error)
	AddUserProvider(*models.MfaUserProvider) error
	GetUserProviders(*models.User) ([]*models.MfaProvider, error)
}

type MfaService struct {
	db *mgo.Database
}

func NewMfaService(dbHandler *mgo.Session) *MfaService {
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
