package entity

import (
	"time"
)

type AppID string

// Application describes a table for storing the basic properties and settings of the authorization application.
type Application struct {
	// ID is the id for application
	ID AppID

	// SpaceId is the identifier of the space to which the application belongs.
	SpaceID SpaceID

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

	// WebHook endpoint URLs
	WebHooks []string
}
