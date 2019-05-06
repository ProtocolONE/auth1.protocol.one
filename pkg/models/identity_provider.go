package models

import (
	"github.com/globalsign/mgo/bson"
	"go.uber.org/zap/zapcore"
)

type AppIdentityProvider struct {
	ID                  bson.ObjectId `bson:"_id" json:"id"`
	ApplicationID       bson.ObjectId `bson:"app_id" json:"application_id"`
	DisplayName         string        `bson:"display_name" json:"display_name"`
	Name                string        `bson:"name" json:"name"`
	Type                string        `bson:"type" json:"type"`
	ClientID            string        `bson:"client_id" json:"client_id"`
	ClientSecret        string        `bson:"client_secret" json:"client_secret"`
	ClientScopes        []string      `bson:"client_scopes" json:"client_scopes"`
	EndpointAuthURL     string        `bson:"endpoint_auth_url" json:"endpoint_auth_url"`
	EndpointTokenURL    string        `bson:"endpoint_token_url" json:"endpoint_token_url"`
	EndpointUserInfoURL string        `bson:"endpoint_userinfo_url" json:"endpoint_userinfo_url"`
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
