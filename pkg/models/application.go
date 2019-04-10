package models

import (
	"github.com/globalsign/mgo/bson"
	"go.uber.org/zap/zapcore"
	"time"
)

var (
	PasswordBcryptCostDefault     = 8
	PasswordMinDefault            = 4
	PasswordMaxDefault            = 30
	PasswordRequireNumberDefault  = true
	PasswordRequireUpperDefault   = true
	PasswordRequireSpecialDefault = false
	PasswordTokenLengthDefault    = 128
	PasswordTokenTTLDefault       = 3600

	AppIdentityProviderTypePassword = "password"
	AppIdentityProviderTypeSocial   = "social"

	AppIdentityProviderNameDefault  = "initial"
	AppIdentityProviderNameFacebook = "facebook"
	AppIdentityProviderNameTwitch   = "twitch"
	AppIdentityProviderNameGoogle   = "google"
	AppIdentityProviderNameVk       = "vk"

	AppIdentityProviderDisplayNameDefault  = "Initial connection"
	AppIdentityProviderDisplayNameFacebook = "Facebook"
	AppIdentityProviderDisplayNameTwitch   = "Twitch"
	AppIdentityProviderDisplayNameGoogle   = "Google"
	AppIdentityProviderDisplayNameVk       = "VKontakte"
)

type Application struct {
	ID                bson.ObjectId          `bson:"_id" json:"id"`
	SpaceId           bson.ObjectId          `bson:"space_id" json:"space_id"`
	Name              string                 `bson:"name" json:"name" validate:"required"`
	Description       string                 `bson:"description" json:"description"`
	IsActive          bool                   `bson:"is_active" json:"is_active"`
	CreatedAt         time.Time              `bson:"created_at" json:"-"`
	UpdatedAt         time.Time              `bson:"updated_at" json:"-"`
	AuthSecret        string                 `bson:"auth_secret" json:"auth_secret" validate:"required"`
	AuthRedirectUrls  []string               `bson:"auth_redirect_urls" json:"auth_redirect_urls" validate:"required"`
	HasSharedUsers    bool                   `bson:"has_shared_users" json:"has_shared_users"`
	PasswordSettings  *PasswordSettings      `bson:"password_settings" json:"password_settings"`
	IdentityProviders []*AppIdentityProvider `bson:"identity_providers" json:"identity_providers"`
}

type PasswordSettings struct {
	BcryptCost     int  `bson:"bcrypt_cost" json:"bcrypt_cost"`
	Min            int  `bson:"min" json:"min"`
	Max            int  `bson:"max" json:"max"`
	RequireNumber  bool `bson:"require_number" json:"require_number"`
	RequireUpper   bool `bson:"require_upper" json:"require_upper"`
	RequireSpecial bool `bson:"require_special" json:"require_special"`
	TokenLength    int  `bson:"token_length" json:"token_length"`
	TokenTTL       int  `bson:"token_ttl" json:"token_ttl"`
}

func (a *Application) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("ID", a.ID.String())
	enc.AddString("SpaceId", a.SpaceId.String())
	enc.AddString("Name", a.Name)
	enc.AddString("Description", a.Description)
	enc.AddBool("IsActive", a.IsActive)
	enc.AddTime("CreatedAt", a.CreatedAt)
	enc.AddTime("UpdatedAt", a.UpdatedAt)
	enc.AddBool("HasSharedUsers", a.HasSharedUsers)

	return nil
}

func (ps *PasswordSettings) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddInt("BcryptCost", ps.BcryptCost)
	enc.AddInt("Min", ps.Min)
	enc.AddInt("Max", ps.Max)
	enc.AddBool("RequireNumber", ps.RequireNumber)
	enc.AddBool("RequireUpper", ps.RequireUpper)
	enc.AddBool("RequireSpecial", ps.RequireSpecial)
	enc.AddInt("TokenLength", ps.TokenLength)
	enc.AddInt("TokenTTL", ps.TokenTTL)

	return nil
}
