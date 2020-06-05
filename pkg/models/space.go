package models

import (
	"time"

	"github.com/globalsign/mgo/bson"
	"go.uber.org/zap/zapcore"
)

type Space struct {
	ID          bson.ObjectId `bson:"_id" json:"id"`                        // unique space identifier
	Name        string        `bson:"name" json:"name" validate:"required"` // space name
	Description string        `bson:"description" json:"description"`       // space description
	IsActive    bool          `bson:"is_active" json:"is_active"`           // is space active

	// UniqueUsernames determines whether app users must have unique usernames
	UniqueUsernames bool `bson:"unique_usernames" json:"unique_usernames"`

	// RequiresCaptcha determines whether app users must have complete captcha verification
	RequiresCaptcha bool `bson:"requires_captcha" json:"requires_captcha"`

	// IdentityProviders contains a list of valid authorization providers for the application, for example using a
	// local database, an external social authentication service (facebook, google and etc), SAML, and others.
	IdentityProviders []*AppIdentityProvider `bson:"identity_providers" json:"identity_providers"`

	CreatedAt time.Time `bson:"created_at" json:"-"` // date of create space
	UpdatedAt time.Time `bson:"updated_at" json:"-"` // date of update space
}

func (s *Space) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("id", s.ID.String())
	enc.AddString("name", s.Name)
	enc.AddString("description", s.Name)
	enc.AddBool("isActive", s.IsActive)

	return nil
}
