package service

import (
	"github.com/ProtocolONE/auth1.protocol.one/pkg/database"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/models"
	"github.com/globalsign/mgo"
	"github.com/globalsign/mgo/bson"
)

type SpaceService struct {
	db *mgo.Database
}

func NewSpaceService(dbHandler *mgo.Session) *SpaceService {
	return &SpaceService{db: dbHandler.DB("")}
}

func (ss SpaceService) CreateSpace(space *models.Space) error {
	if err := ss.db.C(database.TableSpace).Insert(space); err != nil {
		return err
	}

	return nil
}

func (ss SpaceService) UpdateSpace(space *models.Space) error {
	if err := ss.db.C(database.TableSpace).UpdateId(space.Id, space); err != nil {
		return err
	}

	return nil
}

func (ss SpaceService) GetSpace(id bson.ObjectId) (*models.Space, error) {
	s := &models.Space{}
	if err := ss.db.C(database.TableSpace).
		FindId(id).
		One(&s); err != nil {
		return nil, err
	}

	return s, nil
}
