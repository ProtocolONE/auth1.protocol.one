package models

import (
	"github.com/globalsign/mgo/bson"
	"go.uber.org/zap/zapcore"
)

// AppIdentityProvider describes a table for storing the basic properties of the application provider.
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

func (ipc *AppIdentityProvider) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("ID", ipc.ID.String())
	enc.AddString("ApplicationID", ipc.ApplicationID.String())
	enc.AddString("DisplayName", ipc.DisplayName)
	enc.AddString("Name", ipc.Name)
	enc.AddString("Type", ipc.Type)
	enc.AddString("ClientID", ipc.ClientID)
	enc.AddString("ClientSecret", ipc.ClientSecret)
	enc.AddReflected("ClientScopes", ipc.ClientScopes)
	enc.AddString("EndpointAuthURL", ipc.EndpointAuthURL)
	enc.AddString("EndpointTokenURL", ipc.EndpointTokenURL)
	enc.AddString("EndpointUserInfoURL", ipc.EndpointUserInfoURL)

	return nil
}
