package models

import (
	"github.com/globalsign/mgo/bson"
	"go.uber.org/zap/zapcore"
)

type MfaAuthenticator struct {
	ID            bson.ObjectId `json:"id"`
	Secret        string        `json:"secret"`
	ObbChannel    string        `json:"oob_channel,omitempty"`
	BarcodeUri    string        `json:"barcode_uri,omitempty"`
	Type          string        `json:"authenticator_type"`
	RecoveryCodes []string      `json:"recovery_codes"`
}

type MfaChallengeForm struct {
	ClientId   string `json:"client_id" form:"client_id" validate:"required"`
	Connection string `json:"connection" form:"connection" validate:"required"`
	Token      string `json:"mfa_token" form:"mfa_token" validate:"required"`
	Type       string `json:"challenge_type" form:"challenge_type"`
}

type MfaVerifyForm struct {
	ClientId   string `json:"client_id" form:"client_id" validate:"required"`
	ProviderId string `json:"provider_id" form:"provider_id" validate:"required"`
	Token      string `json:"mfa_token" form:"mfa_token" validate:"required"`
	Code       string `json:"code" form:"code"`
}

type MfaAddForm struct {
	ClientId    string `json:"client_id" form:"client_id" validate:"required"`
	ProviderId  string `json:"provider_id" form:"provider_id" validate:"required"`
	Code        string `json:"code" form:"code"`
	PhoneNumber string `json:"phone_number" form:"phone_number"`
}

type MfaApplicationForm struct {
	AppId       bson.ObjectId               `json:"app_id" validate:"required"`
	MfaProvider *MfaApplicationProviderForm `json:"mfa_provider" validate:"required"`
}

type MfaApplicationProviderForm struct {
	Name    string `bson:"name" json:"name" validate:"required"`
	Channel string `bson:"channel" json:"channel"`
	Type    string `bson:"type" json:"type"`
}

type MfaProvider struct {
	ID      bson.ObjectId `bson:"_id" json:"id"`
	AppID   bson.ObjectId `bson:"app_id" json:"app_id"`
	Name    string        `bson:"name" json:"name"`
	Type    string        `bson:"type" json:"type"`
	Channel string        `bson:"channel" json:"channel"`
}

type MfaUserProvider struct {
	UserID     bson.ObjectId `bson:"user_id" json:"user_id"`
	ProviderID bson.ObjectId `bson:"provider_id" json:"provider_id"`
}

type UserMfaToken struct {
	UserIdentity *UserIdentity
	MfaProvider  *MfaProvider
}

type MfaConnection struct {
	Name    string `bson:"name" json:"name"`
	Type    string `bson:"type" json:"type"`
	Channel string `bson:"channel" json:"channel"`
}

func (m *MfaProvider) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("ID", m.ID.String())
	enc.AddString("ApplicationID", m.AppID.String())
	enc.AddString("Name", m.Name)
	enc.AddString("Type", m.Type)
	enc.AddString("Channel", m.Channel)
	return nil
}

func (m *MfaVerifyForm) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("ID", m.ClientId)
	enc.AddString("ApplicationID", m.ProviderId)
	enc.AddString("Token", "[HIDDEN]")
	enc.AddString("Code", "[HIDDEN]")

	return nil
}

func (m *MfaAddForm) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("ID", m.ClientId)
	enc.AddString("ProviderId", m.ProviderId)
	enc.AddString("Code", m.Code)
	enc.AddString("PhoneNumber", "[HIDDEN]")

	return nil
}

func (m *MfaApplicationForm) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("ID", m.AppId.String())
	return enc.AddObject("MfaProvider", m.MfaProvider)
}

func (m *MfaApplicationProviderForm) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("Name", m.Name)
	enc.AddString("Channel", m.Channel)
	enc.AddString("Type", m.Type)

	return nil
}

func (m *MfaChallengeForm) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("ClientId", m.ClientId)
	enc.AddString("Name", m.Connection)
	enc.AddString("Type", m.Type)
	enc.AddString("Token", m.Token)

	return nil
}
