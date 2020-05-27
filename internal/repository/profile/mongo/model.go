package mongo

import (
	"errors"
	"time"

	"github.com/ProtocolONE/auth1.protocol.one/internal/domain/entity"
	"github.com/globalsign/mgo/bson"
)

type model struct {
	// ID is the id of profile.
	ID bson.ObjectId `bson:"_id" json:"id"`
	// UserID is user's id
	UserID bson.ObjectId `bson:"user_id" json:"user_id"`

	//
	Address1 *string `bson:"address_1" json:"address_1"`
	Address2 *string `bosn:"address_2" json:"address_2"`
	City     *string `bson:"city" json:"city"`
	State    *string `bson:"state" json:"state"`
	Country  *string `bson:"country" json:"country"`
	Zip      *string `bson:"zip" json:"zip"`
	//
	PhotoURL  *string    `bson:"photo_url" json:"photo_url"`
	FirstName *string    `bson:"first_name" json:"first_name"`
	LastName  *string    `bson:"last_name" json:"last_name"`
	BirthDate *time.Time `bson:"birth_date" json:"birth_date"`
	//
	Language *string `bson:"language" json:"language"`
}

func (m model) Convert() *entity.Profile {
	return &entity.Profile{
		UserID: m.UserID.Hex(),
		//
		Address1: m.Address1,
		Address2: m.Address2,
		City:     m.City,
		State:    m.State,
		Country:  m.Country,
		Zip:      m.Zip,
		//
		PhotoURL:  m.PhotoURL,
		FirstName: m.FirstName,
		LastName:  m.LastName,
		BirthDate: m.BirthDate,
		//
		Language: m.Language,
	}
}

func newModel(i *entity.Profile) (*model, error) {
	if i.UserID == "" {
		return nil, errors.New("Profile.UserID is empty")
	}
	return &model{
		ID:     bson.ObjectIdHex(i.UserID),
		UserID: bson.ObjectIdHex(i.UserID),
		//
		Address1: i.Address1,
		Address2: i.Address2,
		City:     i.City,
		State:    i.State,
		Country:  i.Country,
		Zip:      i.Zip,
		//
		PhotoURL:  i.PhotoURL,
		FirstName: i.FirstName,
		LastName:  i.LastName,
		BirthDate: i.BirthDate,
		//
		Language: i.Language,
	}, nil
}
