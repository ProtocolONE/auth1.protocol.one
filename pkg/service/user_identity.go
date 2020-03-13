package service

import (
	"github.com/ProtocolONE/auth1.protocol.one/pkg/database"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/models"
	"github.com/globalsign/mgo"
	"github.com/globalsign/mgo/bson"
)

// UserIdentityServiceInterface describes of methods for the user identity service.
type UserIdentityServiceInterface interface {
	// Create creates a new user identity.
	Create(*models.UserIdentity) error

	// Update updates user identity data.
	Update(*models.UserIdentity) error

	// Get return the user identity by id.
	Get(*models.Application, *models.AppIdentityProvider, string) (*models.UserIdentity, error)

	// FindByUser return identity by userId
	FindByUser(app *models.Application, ip *models.AppIdentityProvider, userId bson.ObjectId) (*models.UserIdentity, error)
}

// UserIdentityService is the user identity service.
type UserIdentityService struct {
	db *mgo.Database
}

// NewUserIdentityService return new user identity service.
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

func (us UserIdentityService) FindByUser(app *models.Application, ip *models.AppIdentityProvider, userId bson.ObjectId) (*models.UserIdentity, error) {
	ui := &models.UserIdentity{}
	if err := us.db.C(database.TableUserIdentity).
		Find(bson.M{"app_id": app.ID, "identity_provider_id": ip.ID, "user_id": userId}).
		One(&ui); err != nil {
		return nil, err
	}

	return ui, nil
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
