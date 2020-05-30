package entity

import "time"

type UserIdentityID string

// UserIdentity describes a table for storing the basic properties of the user identifier.
type UserIdentity struct {
	// ID is the id of identity.
	ID UserIdentityID

	// UserID is the id of the user.
	UserID UserID

	// IdentityProviderID is the id of identity provider.
	IdentityProviderID IdentityProviderID

	// ExternalID is the id of external network (like a facebook user id).
	ExternalID string

	// Credential is the
	Credential string

	// Email is the email address of the user.
	Email string

	// Username is the nickname of the user.
	Username string

	// Name is the name of the user. Contains first anf last name.
	Name string

	// Picture is the avatar of the user.
	Picture string

	// Friends is a list of the friends to external network.
	Friends []string

	// CreatedAt returns the timestamp of the user identity creation.
	CreatedAt time.Time

	// UpdatedAt returns the timestamp of the last update.
	UpdatedAt time.Time
}
