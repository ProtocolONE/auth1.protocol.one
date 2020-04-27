package mongo

import (
	"errors"
	"time"

	"github.com/ProtocolONE/auth1.protocol.one/internal/domain/entity"
	"github.com/globalsign/mgo/bson"
)

type model struct {
	// ID is the id of identity.
	ID bson.ObjectId `bson:"_id" json:"id"`

	// UserID is the id of the user.
	UserID bson.ObjectId `bson:"user_id" json:"user_id"`

	// ApplicationID is the id of the application.
	ApplicationID bson.ObjectId `bson:"app_id" json:"app_id"`

	// IdentityProviderID is the id of identity provider.
	IdentityProviderID bson.ObjectId `bson:"identity_provider_id" json:"identity_provider_id" validate:"required"`

	// ExternalID is the id of external network (like a facebook user id).
	ExternalID string `bson:"external_id" json:"external_id"`

	// Credential is the
	Credential *string `bson:"credential" json:"-" validate:"required"`

	// Email is the email address of the user.
	Email *string `bson:"email" json:"email" validate:"required,email"`

	// Username is the nickname of the user.
	Username *string `bson:"username" json:"username"`

	// Name is the name of the user. Contains first anf last name.
	Name *string `bson:"name" json:"name"`

	// Picture is the avatar of the user.
	Picture *string `bson:"picture" json:"picture"`

	// Friends is a list of the friends to external network.
	Friends []string `bson:"friends" json:"friends"`

	// CreatedAt returns the timestamp of the user identity creation.
	CreatedAt time.Time `bson:"created_at" json:"created_at"`

	// UpdatedAt returns the timestamp of the last update.
	UpdatedAt *time.Time `bson:"updated_at" json:"updated_at"`
}

func (m model) Convert() *entity.UserIdentity {
	return &entity.UserIdentity{
		ID:                 m.ID.Hex(),
		UserID:             m.UserID.Hex(),
		ApplicationID:      m.ApplicationID.Hex(),
		IdentityProviderID: m.IdentityProviderID.Hex(),
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
	if i.ApplicationID == "" {
		return nil, errors.New("UserIdentity.ApplicationID is empty")
	}
	if i.IdentityProviderID == "" {
		return nil, errors.New("UserIdentity.IdentityProviderID is empty")
	}
	return &model{
		ID:                 bson.ObjectIdHex(i.ID),
		UserID:             bson.ObjectIdHex(i.UserID),
		ApplicationID:      bson.ObjectIdHex(i.ApplicationID),
		IdentityProviderID: bson.ObjectIdHex(i.IdentityProviderID),
		ExternalID:         i.ExternalID,
		Credential:         i.Credential,
		Email:              i.Email,
		Username:           i.Username,
		Name:               i.Name,
		Picture:            i.Picture,
		Friends:            i.Friends,
	}, nil
}
