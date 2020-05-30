package mongo

import (
	"time"

	"github.com/ProtocolONE/auth1.protocol.one/internal/domain/entity"
	"github.com/globalsign/mgo/bson"
)

type model struct {
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

	// WebHook endpoint URLs
	WebHooks []string `bson:"webhooks" json:"webhooks"`
}

func (m model) Convert() *entity.Application {
	passSettings := &entity.PasswordSettings{}
	if m.PasswordSettings != nil {
		passSettings.BcryptCost = m.PasswordSettings.BcryptCost
		passSettings.Max = m.PasswordSettings.Max
		passSettings.Min = m.PasswordSettings.Min
		passSettings.TokenLength = m.PasswordSettings.TokenLength
		passSettings.TokenTTL = m.PasswordSettings.TokenTTL
		passSettings.RequireNumber = m.PasswordSettings.RequireNumber
		passSettings.RequireSpecial = m.PasswordSettings.RequireSpecial
		passSettings.RequireUpper = m.PasswordSettings.RequireUpper
	}

	otSettings := &entity.OneTimeTokenSettings{}
	if m.OneTimeTokenSettings != nil {
		otSettings.TTL = m.OneTimeTokenSettings.TTL
		otSettings.Length = m.OneTimeTokenSettings.Length
	}

	return &entity.Application{
		ID:                     m.ID.Hex(),
		SpaceId:                m.SpaceId.Hex(),
		Name:                   m.Name,
		Description:            m.Description,
		IsActive:               m.IsActive,
		CreatedAt:              m.CreatedAt,
		UpdatedAt:              m.UpdatedAt,
		AuthSecret:             m.AuthSecret,
		AuthRedirectUrls:       m.AuthRedirectUrls,
		PostLogoutRedirectUrls: m.PostLogoutRedirectUrls,
		HasSharedUsers:         m.HasSharedUsers,
		UniqueUsernames:        m.UniqueUsernames,
		RequiresCaptcha:        m.RequiresCaptcha,
		PasswordSettings:       passSettings,
		OneTimeTokenSettings:   otSettings,
		WebHooks:               m.WebHooks,
	}

}

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

type OneTimeTokenSettings struct {
	// Length is the length of token.
	Length int `bson:"length" json:"length"`

	//TTL is the expiration time for the token.
	TTL int `bson:"ttl" json:"ttl"`
}

type AppIdentityProvider struct {
	// ID is the id of provider.
	ID bson.ObjectId `bson:"_id" json:"id"`

	// ApplicationID is the id of application.
	ApplicationID bson.ObjectId `bson:"app_id" json:"application_id"`

	// DisplayName is the human-readable string name of the provider.
	DisplayName string `bson:"display_name" json:"display_name"`

	// Name is the service name used in authorization requests. It must not contain spaces and special characters.
	Name string `bson:"name" json:"name"`

	// Type defines the type of provider, such as a password(password) or social authorization(social).
	Type string `bson:"type" json:"type"`

	// ClientID is the client identifier on external network. For example, the application ID in Facebook.
	ClientID string `bson:"client_id" json:"client_id"`

	// ClientSecret is the secret string of the client on external network.
	ClientSecret string `bson:"client_secret" json:"client_secret"`

	// ClientScopes is the scopes list for external network.
	ClientScopes []string `bson:"client_scopes" json:"client_scopes"`

	// EndpointAuthURL is the authentication url on external network.
	EndpointAuthURL string `bson:"endpoint_auth_url" json:"endpoint_auth_url"`

	// EndpointTokenURL is the endpoint url on external network for exchange authentication code to the tokens.
	EndpointTokenURL string `bson:"endpoint_token_url" json:"endpoint_token_url"`

	// EndpointUserInfoURL is the endpoint on external network for to get user information.
	EndpointUserInfoURL string `bson:"endpoint_userinfo_url" json:"endpoint_userinfo_url"`
}
