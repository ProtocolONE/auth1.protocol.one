package service

import (
	"github.com/ProtocolONE/auth1.protocol.one/pkg/database"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/models"
	"github.com/globalsign/mgo"
	"github.com/globalsign/mgo/bson"
)

// UserServiceInterface describes of methods for the user service.
type UserServiceInterface interface {
	// Create creates a new user.
	Create(*models.User) error

	// Update updates user data.
	Update(*models.User) error

	// Get return the user by id.
	Get(bson.ObjectId) (*models.User, error)

	// IsUsernameFree checks if username is available for signup
	IsUsernameFree(username string, appID bson.ObjectId) (bool, error)
}

// UserService is the user service.
type UserService struct {
	db *mgo.Database
}

// NewUserService return new user service.
func NewUserService(dbHandler database.MgoSession) *UserService {
	return &UserService{db: dbHandler.DB("")}
}

func (us UserService) Create(user *models.User) error {
	if err := us.db.C(database.TableUser).Insert(user); err != nil {
		return err
	}

	return nil
}

func (us UserService) Update(user *models.User) error {
	if err := us.db.C(database.TableUser).UpdateId(user.ID, user); err != nil {
		return err
	}

	return nil
}

func (us UserService) Get(id bson.ObjectId) (*models.User, error) {
	u := &models.User{}
	if err := us.db.C(database.TableUser).
		FindId(id).
		One(&u); err != nil {
		return nil, err
	}

	return u, nil
}

func (us UserService) IsUsernameFree(username string, appID bson.ObjectId) (bool, error) {
	// TODO: Optimize for case when multiple same username allowed
	n, err := us.db.C(database.TableUser).Find(bson.M{"username": username, "app_id": appID}).Count()
	return n == 0, err
}
