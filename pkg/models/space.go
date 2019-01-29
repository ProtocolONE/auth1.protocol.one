package models

import (
	"auth-one-api/pkg/database"
	"go.uber.org/zap/zapcore"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
	"time"
)

type SpaceService struct {
	db *mgo.Database
}

type Space struct {
	Id          bson.ObjectId `bson:"_id" json:"id"`                        // unique space identifier
	Name        string        `bson:"name" json:"name" validate:"required"` // space name
	Description string        `bson:"description" json:"description"`       // space description
	IsActive    bool          `bson:"is_active" json:"is_active"`           // is space active
	CreatedAt   time.Time     `bson:"created_at" json:"-"`                  // date of create space
	UpdatedAt   time.Time     `bson:"updated_at" json:"-"`                  // date of update space
}

type SpaceForm struct {
	Name        string `bson:"name" json:"name" validate:"required"` // space name
	Description string `bson:"description" json:"description"`       // space description
	IsActive    bool   `bson:"is_active" json:"is_active"`           // is space active
}

func (s *Space) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("id", s.Id.String())
	enc.AddString("name", s.Name)
	enc.AddString("description", s.Name)
	enc.AddBool("isActive", s.IsActive)
	return nil
}

func NewSpaceService(dbHandler *database.Handler) *SpaceService {
	return &SpaceService{dbHandler.Session.DB(dbHandler.Name)}
}

func (ss SpaceService) CreateSpace(space *Space) error {
	if err := ss.db.C(database.TableSpace).Insert(space); err != nil {
		return err
	}

	return nil
}

func (ss SpaceService) UpdateSpace(space *Space) error {
	if err := ss.db.C(database.TableSpace).UpdateId(space.Id, space); err != nil {
		return err
	}

	return nil
}

func (ss SpaceService) GetSpace(id bson.ObjectId) (*Space, error) {
	s := &Space{}
	if err := ss.db.C(database.TableSpace).
		FindId(id).
		One(&s); err != nil {
		return nil, err
	}

	return s, nil
}
