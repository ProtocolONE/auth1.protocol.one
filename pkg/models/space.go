package models

import (
	"auth-one-api/pkg/database"
	"github.com/globalsign/mgo"
	"github.com/globalsign/mgo/bson"
	"go.uber.org/zap/zapcore"
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

func (s *SpaceForm) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("Name", s.Name)
	enc.AddString("Description", s.Description)
	enc.AddBool("IsActive", s.IsActive)

	return nil
}

func NewSpaceService(dbHandler *mgo.Session) *SpaceService {
	return &SpaceService{db: dbHandler.DB("")}
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
