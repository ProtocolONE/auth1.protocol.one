package models

import (
	"auth-one-api/pkg/database"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
	"time"
)

type (
	ApplicationService struct {
		db *mgo.Database
	}

	Application struct {
		Id          bson.ObjectId `bson:"_id" json:"id"`                        // unique application identifier
		SpaceId     bson.ObjectId `bson:"space_id" json:"space_id"`             // application space owner
		Name        string        `bson:"name" json:"name" validate:"required"` // application name
		Description string        `bson:"description" json:"description"`       // application description
		IsActive    bool          `bson:"is_active" json:"is_active"`           // is application active
		CreatedAt   time.Time     `bson:"created_at" json:"-"`                  // date of create application
		UpdatedAt   time.Time     `bson:"updated_at" json:"-"`                  // date of update application
	}

	ApplicationForm struct {
		SpaceId     bson.ObjectId       `json:"space_id"`                        // unique space identifier
		Application *ApplicationFormApp `json:"application" validate:"required"` // application data
	}

	ApplicationFormApp struct {
		Name        string `bson:"name" json:"name" validate:"required"` // application name
		Description string `bson:"description" json:"description"`       // application description
		IsActive    bool   `bson:"is_active" json:"is_active"`           // is application active
	}
)

func NewApplicationService(h *database.Handler) *ApplicationService {
	return &ApplicationService{h.Session.DB(h.Name)}
}

func (s ApplicationService) Create(a *Application) error {
	if err := s.db.C(database.TableApplication).Insert(a); err != nil {
		return err
	}

	return nil
}

func (s ApplicationService) Update(a *Application) error {
	if err := s.db.C(database.TableApplication).UpdateId(a.Id, a); err != nil {
		return err
	}

	return nil
}

func (s ApplicationService) Get(id bson.ObjectId) (*Application, error) {
	a := &Application{}
	if err := s.db.C(database.TableApplication).
		FindId(id).
		One(&a); err != nil {
		return nil, err
	}

	return a, nil
}
