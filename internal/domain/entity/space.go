package entity

import (
	"time"
)

type SpaceID string

// Space is authentication realm
type Space struct {
	// unique space identifier
	ID SpaceID

	// space name
	Name string

	// space description
	Description string

	// UniqueUsernames determines whether space users must have unique usernames
	UniqueUsernames bool

	// RequiresCaptcha determines whether space users must have complete captcha verification
	RequiresCaptcha bool

	// Password requirements
	PasswordSettings PasswordSettings

	// IdentityProviders contains a list of valid authorization providers for the application, for example using a
	// local database, an external social authentication service (facebook, google and etc), SAML, and others.
	IdentityProviders

	// date of creation
	CreatedAt time.Time

	// date of last update
	UpdatedAt time.Time
}

// NewSpace creates space with default params
func NewSpace() *Space {
	now := time.Now()
	return &Space{
		Name:              "",
		Description:       "",
		UniqueUsernames:   true,
		RequiresCaptcha:   false,
		PasswordSettings:  DefaultPasswordSettings,
		IdentityProviders: NewIdentityProviders(),
		CreatedAt:         now,
		UpdatedAt:         now,
	}
}
