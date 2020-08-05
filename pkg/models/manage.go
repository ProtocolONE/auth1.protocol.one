package models

import (
	"github.com/globalsign/mgo/bson"
	"go.uber.org/zap/zapcore"
)

type ApplicationForm struct {
	SpaceId     bson.ObjectId       `json:"space_id"`                        // unique space identifier
	Application *ApplicationFormApp `json:"application" validate:"required"` // application data
}

func (a *ApplicationForm) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("SpaceId", a.SpaceId.String())
	enc.AddObject("Application", a.Application)

	return nil
}

type ApplicationFormApp struct {
	Name                   string   `bson:"name" json:"name" validate:"required"`
	Description            string   `bson:"description" json:"description"`
	IsActive               bool     `bson:"is_active" json:"is_active"`
	AuthRedirectUrls       []string `bson:"auth_redirect_urls" json:"auth_redirect_urls" validate:"required"`
	PostLogoutRedirectUrls []string `bson:"post_logout_redirect_urls" json:"post_logout_redirect_urls"`
	HasSharedUsers         bool     `bson:"has_shared_users" json:"has_shared_users"`
	UniqueUsernames        bool     `bson:"unique_usernames" json:"unique_usernames"`
	RequiresCaptcha        bool     `bson:"requires_captcha" json:"requires_captcha"`
	Webhooks               []string `bson:"webhooks" json:"webhooks"`
}

func (a *ApplicationFormApp) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("Name", a.Name)
	enc.AddString("Description", a.Description)
	enc.AddBool("IsActive", a.IsActive)

	return nil
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
