package service

import (
	"github.com/ProtocolONE/auth1.protocol.one/pkg/database"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/models"
	"github.com/globalsign/mgo"
	"github.com/globalsign/mgo/bson"
)

type UserServiceInterface interface {
	Create(*models.User) error
	Update(*models.User) error
	Get(bson.ObjectId) (*models.User, error)
}

type UserService struct {
	db *mgo.Database
}

func NewUserService(dbHandler *mgo.Session) *UserService {
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
