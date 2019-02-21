package models

import (
	"github.com/globalsign/mgo/bson"
	"go.uber.org/zap/zapcore"
)

type ApplicationForm struct {
	SpaceId     bson.ObjectId       `json:"space_id"`                        // unique space identifier
	Application *ApplicationFormApp `json:"application" validate:"required"` // application data
}

type ApplicationFormApp struct {
	Name             string   `bson:"name" json:"name" validate:"required"`                             // application name
	Description      string   `bson:"description" json:"description"`                                   // application description
	IsActive         bool     `bson:"is_active" json:"is_active"`                                       // is application active
	AuthRedirectUrls []string `bson:"auth_redirect_urls" json:"auth_redirect_urls" validate:"required"` // auth secret key
}

type ApplicationKeysForm struct {
	ApplicationId string `json:"application_id" validate:"required"` // application id
	Algorithm     string `json:"algorithm" validate:"required"`      // algorithm name (HS256, HS512, RS256, ECDSA)
}

func (a *ApplicationKeysForm) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("ApplicationID", a.ApplicationId)
	enc.AddString("Algorithm", a.Algorithm)

	return nil
}
