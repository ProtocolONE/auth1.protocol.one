package service

import (
	"github.com/ProtocolONE/auth1.protocol.one/pkg/database"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/models"
	"github.com/globalsign/mgo"
	"github.com/globalsign/mgo/bson"
)

type UserIdentityServiceInterface interface {
	Create(*models.UserIdentity) error
	Update(*models.UserIdentity) error
	Get(*models.Application, *models.AppIdentityProvider, string) (*models.UserIdentity, error)
}

type UserIdentityService struct {
	db *mgo.Database
}

func NewUserIdentityService(dbHandler database.MgoSession) *UserIdentityService {
	return &UserIdentityService{db: dbHandler.DB("")}
}

func (us UserIdentityService) Create(userIdentity *models.UserIdentity) error {
	if err := us.db.C(database.TableUserIdentity).Insert(userIdentity); err != nil {

		return err
	}

	return nil
}

func (us UserIdentityService) Update(userIdentity *models.UserIdentity) error {
	if err := us.db.C(database.TableUserIdentity).UpdateId(userIdentity.ID, userIdentity); err != nil {
		return err
	}

	return nil
}

func (us UserIdentityService) Get(app *models.Application, identityProvider *models.AppIdentityProvider, externalId string) (*models.UserIdentity, error) {
	ui := &models.UserIdentity{}
	if err := us.db.C(database.TableUserIdentity).
		Find(bson.M{"app_id": app.ID, "identity_provider_id": identityProvider.ID, "external_id": externalId}).
		One(&ui); err != nil {
		return nil, err
	}

	return ui, nil
}
