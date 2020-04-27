package entity

type UserIdentity struct {
	ID     string
	UserID string
	//
	ApplicationID      string
	IdentityProviderID string
	ExternalID         string
	//
	Credential *string
	Email      *string
	Username   *string
	Name       *string
	Picture    *string
	Friends    []string
}
