package models

import (
	"time"

	"github.com/globalsign/mgo/bson"
	"go.uber.org/zap/zapcore"
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

	// HasSharedUsers determines whether users are shared across the entire space or only within the application.
	// If this option is set, then users from other applications (in space) will be able to log in to this application.
	HasSharedUsers bool `bson:"has_shared_users" json:"has_shared_users"`

	// UniqueUsernames determines whether app users must have unique usernames
	UniqueUsernames bool `bson:"unique_usernames" json:"unique_usernames"`

	// RequiresCaptcha determines whether app users must have complete captcha verification
	RequiresCaptcha bool `bson:"requires_captcha" json:"requires_captcha"`

	// PasswordSettings contains settings for valid password criteria.
	PasswordSettings *PasswordSettings `bson:"password_settings" json:"password_settings"`

	// OneTimeTokenSettings contains settings for storing one-time application tokens.
	OneTimeTokenSettings *OneTimeTokenSettings `bson:"ott_settings" json:"ott_settings"`

	// IdentityProviders contains a list of valid authorization providers for the application, for example using a
	// local database, an external social authentication service (facebook, google and etc), SAML, and others.
	IdentityProviders []*AppIdentityProvider `bson:"identity_providers" json:"identity_providers"`
}

// PasswordSettings contains settings for valid password criteria.
type PasswordSettings struct {
	// BcryptCost determines the depth of password encryption for providers based on the database.
	// CPU load and performance depend on the BCrypt cost.
	BcryptCost int `bson:"bcrypt_cost" json:"bcrypt_cost"`

	// Min is the minimal length password.
	Min int `bson:"min" json:"min"`

	// Max is the maximum length password.
	Max int `bson:"max" json:"max"`

	// RequireNumber requires numbers in the password.
	RequireNumber bool `bson:"require_number" json:"require_number"`

	// RequireUpper requires a capital letter in the password.
	RequireUpper bool `bson:"require_upper" json:"require_upper"`

	// RequireSpecial requires special characters in the password (~,!, @, and the like).
	RequireSpecial bool `bson:"require_special" json:"require_special"`

	// TokenLength determines the length of the token in the password change letter.
	TokenLength int `bson:"token_length" json:"token_length"`

	// TokenTTL determines the token's lifetime in the password change letter.
	TokenTTL int `bson:"token_ttl" json:"token_ttl"`
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
