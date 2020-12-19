package models

import (
	"time"

	"github.com/globalsign/mgo/bson"
	"go.uber.org/zap/zapcore"
)

// UserIdentity describes a table for storing the basic properties of the user identifier.
type UserIdentity struct {
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
	Credential string `bson:"credential" json:"-" validate:"required"`

	// Email is the email address of the user.
	Email string `bson:"email" json:"email" validate:"required,email"`

	// Username is the nickname of the user.
	Username string `bson:"username" json:"username"`

	// Name is the name of the user. Contains first anf last name.
	Name string `bson:"name" json:"name"`

	// Picture is the avatar of the user.
	Picture string `bson:"picture" json:"picture"`

	// Friends is a list of the friends to external network.
	Friends []string `bson:"friends" json:"friends"`

	// CreatedAt returns the timestamp of the user identity creation.
	CreatedAt time.Time `bson:"created_at" json:"created_at"`

	// UpdatedAt returns the timestamp of the last update.
	UpdatedAt time.Time `bson:"updated_at" json:"updated_at"`
}

// UserIdentitySocial contains a basic set of fields for receiving information from external social networks.
type UserIdentitySocial struct {
	// ID is the id in the external network.
	ID string `json:"id,omitempty"`

	// Name is the nickname or username of the user.
	Name string `json:"name,omitempty"`

	// FirstName is the first name of the user.
	FirstName string `json:"first_name,omitempty"`

	// LastName is the last name of the user.
	LastName string `json:"last_name,omitempty"`

	// Email is the email address of the user.
	Email string `json:"email,omitempty"`

	// Birthday is the date of birthday.
	Birthday string `json:"birthday,omitempty"`

	// Picture is the avatar of the user.
	Picture string `json:"picture,omitempty"`

	// Token is the access token on social network.
	Token string `json:"token,omitempty"`
}

func (u *UserIdentitySocial) HideSensitive() {
	u.ID = ""
	u.Token = ""
}

// SocialSettings contains settings for a one-time token when linking a social account and password provider.
type SocialSettings struct {
	// LinkedTokenLength determines the length of the token.
	LinkedTokenLength int `json:"linked_token_length"`

	// LinkedTTL determines the token's lifetime.
	LinkedTTL int `json:"linked_token_ttl"`
}

func (a *UserIdentity) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("ID", a.ID.String())
	enc.AddString("UserID", a.UserID.String())
	enc.AddString("ApplicationID", a.ApplicationID.String())
	enc.AddString("IdentityProviderID", a.IdentityProviderID.String())
	enc.AddString("ExternalID", a.ExternalID)
	enc.AddString("Credential", a.Credential)
	enc.AddString("Email", a.Email)
	enc.AddString("Username", a.Username)
	enc.AddString("Name", a.Name)
	enc.AddString("Email", a.Email)
	enc.AddTime("CreatedAt", a.CreatedAt)
	enc.AddTime("UpdatedAt", a.UpdatedAt)

	return nil
}

func (a *UserIdentitySocial) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("ID", a.ID)
	enc.AddString("Name", a.Name)
	enc.AddString("Email", a.Email)

	return nil
}
