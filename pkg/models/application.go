package models

import (
	"time"

	"github.com/globalsign/mgo/bson"
	"go.uber.org/zap/zapcore"
)

var (
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

// Application describes a table for storing the basic properties and settings of the authorization application.
type Application struct {
	// ID is the id for application
	ID bson.ObjectId `bson:"_id" json:"id"`

	// SpaceId is the identifier of the space to which the application belongs.
	SpaceId bson.ObjectId `bson:"space_id" json:"space_id"`

	// Name is the human-readable string name of the application to be presented to the end-user during authorization.
	Name string `bson:"name" json:"name" validate:"required"`

	// Description is the human-readable string description of the application and not be presented to the users.
	Description string `bson:"description" json:"description"`

	// IsActive allows you to enable or disable the application for authorization.
	IsActive bool `bson:"is_active" json:"is_active"`

	// CreatedAt returns the timestamp of the application creation.
	CreatedAt time.Time `bson:"created_at" json:"-"`

	// UpdatedAt returns the timestamp of the last update.
	UpdatedAt time.Time `bson:"updated_at" json:"-"`

	// AuthSecret is a secret string with which the application checks the authentication code and
	// exchanges it for an access token.
	AuthSecret string `bson:"auth_secret" json:"auth_secret" validate:"required"`

	// AuthRedirectUrls is an array of allowed redirect urls for the client.
	AuthRedirectUrls []string `bson:"auth_redirect_urls" json:"auth_redirect_urls" validate:"required"`

	// PostLogoutRedirectUris is an array of allowed post logout redirect urls for the client.
	PostLogoutRedirectUrls []string `bson:"post_logout_redirect_urls" json:"post_logout_redirect_urls"`

	// OneTimeTokenSettings contains settings for storing one-time application tokens.
	OneTimeTokenSettings *OneTimeTokenSettings `bson:"ott_settings" json:"ott_settings"`

	// WebHook endpoint URLs
	WebHooks []string `bson:"webhooks" json:"webhooks"`

	// Possible user roles
	Roles []string `bson:"roles" json:"roles"`

	// Default user role on sign up
	DefaultRole string `bson:"default_role" json:"default_role"`
}

func (a *Application) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("ID", a.ID.String())
	enc.AddString("SpaceId", a.SpaceId.String())
	enc.AddString("Name", a.Name)
	enc.AddString("Description", a.Description)
	enc.AddBool("IsActive", a.IsActive)
	enc.AddTime("CreatedAt", a.CreatedAt)
	enc.AddTime("UpdatedAt", a.UpdatedAt)

	return nil
}
