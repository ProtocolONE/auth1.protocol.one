package service

import (
	"github.com/ProtocolONE/auth1.protocol.one/pkg/database"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/models"
	"github.com/globalsign/mgo"
	"github.com/globalsign/mgo/bson"
)

type SpaceServiceInterface interface {
	GetSpace(bson.ObjectId) (*models.Space, error)
}

type SpaceService struct {
	db *mgo.Database
}

func NewSpaceService(dbHandler database.MgoSession) *SpaceService {
	return &SpaceService{db: dbHandler.DB("")}
}

func (ss SpaceService) GetSpace(id bson.ObjectId) (*models.Space, error) {
	var s models.Space
	if err := ss.db.C(database.TableSpace).
		FindId(id).
		One(&s); err != nil {
		return nil, err
	}

	return &s, nil
}
