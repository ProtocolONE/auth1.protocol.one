package models

import (
	"github.com/globalsign/mgo/bson"
	"go.uber.org/zap/zapcore"
	"time"
)

type (
	UserIdentity struct {
		ID                 bson.ObjectId `bson:"_id" json:"id"`
		UserID             bson.ObjectId `bson:"user_id" json:"user_id"`
		ApplicationID      bson.ObjectId `bson:"app_id" json:"app_id"`
		IdentityProviderID bson.ObjectId `bson:"identity_provider_id" json:"identity_provider_id" validate:"required"`
		ExternalID         string        `bson:"external_id" json:"external_id"`
		Credential         string        `bson:"credential" json:"-" validate:"required"`
		Email              string        `bson:"email" json:"email" validate:"required,email"`
		Username           string        `bson:"username" json:"username"`
		Name               string        `bson:"name" json:"name"`
		Picture            string        `bson:"picture" json:"picture"`
		Friends            []string      `bson:"friends" json:"friends"`
		CreatedAt          time.Time     `bson:"created_at" json:"created_at"`
		UpdatedAt          time.Time     `bson:"updated_at" json:"updated_at"`
	}

	UserIdentitySocial struct {
		ID        string `json:"id"`
		Name      string `json:"name"`
		FirstName string `json:"first_name"`
		LastName  string `json:"last_name"`
		Email     string `json:"email"`
		Birthday  string `json:"birthday"`
		Picture   string `json:"picture"`
		Token     string `json:"token"`
	}

	SocialSettings struct {
		LinkedTokenLength int `json:"linked_token_length"`
		LinkedTTL         int `json:"linked_token_ttl"`
	}
)

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
