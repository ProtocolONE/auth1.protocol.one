package entity

import (
	"time"
)

// Application describes a table for storing the basic properties and settings of the authorization application.
type Application struct {
	// ID is the id for application
	ID string

	// SpaceId is the identifier of the space to which the application belongs.
	SpaceId string

	// Name is the human-readable string name of the application to be presented to the end-user during authorization.
	Name string

	// Description is the human-readable string description of the application and not be presented to the users.
	Description string

	// IsActive allows you to enable or disable the application for authorization.
	IsActive bool

	// CreatedAt returns the timestamp of the application creation.
	CreatedAt time.Time

	// UpdatedAt returns the timestamp of the last update.
	UpdatedAt time.Time

	// AuthSecret is a secret string with which the application checks the authentication code and
	// exchanges it for an access token.
	AuthSecret string

	// AuthRedirectUrls is an array of allowed redirect urls for the client.
	AuthRedirectUrls []string

	// PostLogoutRedirectUris is an array of allowed post logout redirect urls for the client.
	PostLogoutRedirectUrls []string

	// HasSharedUsers determines whether users are shared across the entire space or only within the application.
	// If this option is set, then users from other applications (in space) will be able to log in to this application.
	HasSharedUsers bool

	// UniqueUsernames determines whether app users must have unique usernames
	UniqueUsernames bool

	// RequiresCaptcha determines whether app users must have complete captcha verification
	RequiresCaptcha bool

	// PasswordSettings contains settings for valid password criteria.
	PasswordSettings *PasswordSettings

	// OneTimeTokenSettings contains settings for storing one-time application tokens.
	OneTimeTokenSettings *OneTimeTokenSettings

	// IdentityProviders contains a list of valid authorization providers for the application, for example using a
	// local database, an external social authentication service (facebook, google and etc), SAML, and others.
	IdentityProviders []*IdentityProvider

	// WebHook endpoint URLs
	WebHooks []string
}
