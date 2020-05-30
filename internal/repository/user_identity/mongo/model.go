package mongo

import (
	"errors"
	"time"

	"github.com/ProtocolONE/auth1.protocol.one/internal/domain/entity"
	"github.com/globalsign/mgo/bson"
)

type model struct {
	ID                 bson.ObjectId `bson:"_id"`
	UserID             bson.ObjectId `bson:"user_id"`
	IdentityProviderID bson.ObjectId `bson:"identity_provider_id"`
	ExternalID         string        `bson:"external_id"`
	Credential         string        `bson:"credential"`
	Email              string        `bson:"email"`
	Username           string        `bson:"username"`
	Name               string        `bson:"name"`
	Picture            string        `bson:"picture"`
	Friends            []string      `bson:"friends"`
	CreatedAt          time.Time     `bson:"created_at"`
	UpdatedAt          time.Time     `bson:"updated_at"`
}

func (m model) Convert() *entity.UserIdentity {
	return &entity.UserIdentity{
		ID:                 entity.UserIdentityID(m.ID.Hex()),
		UserID:             entity.UserID(m.UserID.Hex()),
		IdentityProviderID: entity.IdentityProviderID(m.IdentityProviderID.Hex()),
		ExternalID:         m.ExternalID,
		Credential:         m.Credential,
		Email:              m.Email,
		Username:           m.Username,
		Name:               m.Name,
		Picture:            m.Picture,
		Friends:            m.Friends,
	}
}

func newModel(i *entity.UserIdentity) (*model, error) {
	if i.ID == "" {
		return nil, errors.New("UserIdentity.ID is empty")
	}
	if i.UserID == "" {
		return nil, errors.New("UserIdentity.UserID is empty")
	}
	if i.IdentityProviderID == "" {
		return nil, errors.New("UserIdentity.IdentityProviderID is empty")
	}
	return &model{
		ID:                 bson.ObjectIdHex(string(i.ID)),
		UserID:             bson.ObjectIdHex(string(i.UserID)),
		IdentityProviderID: bson.ObjectIdHex(string(i.IdentityProviderID)),
		ExternalID:         i.ExternalID,
		Credential:         i.Credential,
		Email:              i.Email,
		Username:           i.Username,
		Name:               i.Name,
		Picture:            i.Picture,
		Friends:            i.Friends,
	}, nil
}
