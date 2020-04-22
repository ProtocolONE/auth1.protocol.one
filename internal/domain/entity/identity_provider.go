package entity

const (
	AppIdentityProviderTypePassword = "password"
	AppIdentityProviderTypeSocial   = "social"

	AppIdentityProviderNameDefault = "initial"
)

type IdentityProvider struct {
	// ID is the id of provider.
	ID string

	// ApplicationID is the id of application.
	ApplicationID string

	// DisplayName is the human-readable string name of the provider.
	DisplayName string

	// Name is the service name used in authorization requests. It must not contain spaces and special characters.
	Name string

	// Type defines the type of provider, such as a password(password) or social authorization(social).
	Type string

	// ClientID is the client identifier on external network. For example, the application ID in Facebook.
	ClientID string

	// ClientSecret is the secret string of the client on external network.
	ClientSecret string

	// ClientScopes is the scopes list for external network.
	ClientScopes []string

	// EndpointAuthURL is the authentication url on external network.
	EndpointAuthURL string

	// EndpointTokenURL is the endpoint url on external network for exchange authentication code to the tokens.
	EndpointTokenURL string

	// EndpointUserInfoURL is the endpoint on external network for to get user information.
	EndpointUserInfoURL string
}
