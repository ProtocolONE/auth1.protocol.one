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

// MfaChallengeForm contains form fields for requesting a mfa challenge.
type MfaChallengeForm struct {
	// ClientID is the application id.
	ClientId string `json:"client_id" form:"client_id" validate:"required"`

	// Connection is the connection name of the application identity provider.
	Connection string `json:"connection" form:"connection" validate:"required"`

	// Token is the one-time token for mfa connection.
	Token string `json:"mfa_token" form:"mfa_token" validate:"required"`

	// Type is the type of mfa challenge (otp, sms).
	Type string `json:"challenge_type" form:"challenge_type"`
}

// MfaVerifyForm contains form fields for requesting to verify mfa challenge.
type MfaVerifyForm struct {
	// ClientID is the application id.
	ClientId string `json:"client_id" form:"client_id" validate:"required"`

	// ProviderId is the id of the mfa provider.
	ProviderId string `json:"provider_id" form:"provider_id" validate:"required"`

	// Token is the one-time token of mfa challenge.
	Token string `json:"mfa_token" form:"mfa_token" validate:"required"`

	// Code is the string of one-time code.
	Code string `json:"code" form:"code"`
}

// MfaVerifyForm contains form fields for requesting to link of mfa provider.
type MfaAddForm struct {
	// ClientID is the application id
	ClientId string `json:"client_id" form:"client_id" validate:"required"`

	// ProviderId is the id of the mfa provider.
	ProviderId string `json:"provider_id" form:"provider_id" validate:"required"`

	// Code is the string of one-time code.
	Code string `json:"code" form:"code"`

	// PhoneNumber is the phone number for which the provider will be associated.
	PhoneNumber string `json:"phone_number" form:"phone_number"`
}

// MfaApplicationForm contains form fields for requesting to add of mfa provider.
type MfaApplicationForm struct {
	// AppId is the application id.
	AppId bson.ObjectId `json:"app_id" validate:"required"`

	// MfaProvider is the MFA provider.
	MfaProvider *MfaApplicationProviderForm `json:"mfa_provider" validate:"required"`
}

// MfaApplicationProviderForm contains form fields for the mfa provider.
type MfaApplicationProviderForm struct {
	// Name is the provider name.
	Name string `bson:"name" json:"name" validate:"required"`

	// Channel is the channel of delivery code.
	Channel string `bson:"channel" json:"channel"`

	// Type is the type of provider (otp, sms).
	Type string `bson:"type" json:"type"`
}

// MfaProvider describes of MFA provider.
type MfaProvider struct {
	// ID is the id of provider.
	ID bson.ObjectId `bson:"_id" json:"id"`

	// AppID is the id of the application.
	AppID bson.ObjectId `bson:"app_id" json:"app_id"`

	// Name is a human-readable name of provider.
	Name string `bson:"name" json:"name"`

	// Type is the type of provider (otp, sms).
	Type string `bson:"type" json:"type"`

	// Channel is the channel of delivery code.
	Channel string `bson:"channel" json:"channel"`
}

// MfaUserProvider creates a connection between the MFA provider and the user.
type MfaUserProvider struct {
	// UserID is the id of the user.
	UserID bson.ObjectId `bson:"user_id" json:"user_id"`

	// ProviderID is the id of the provider.
	ProviderID bson.ObjectId `bson:"provider_id" json:"provider_id"`
}

// UserMfaToken contains link between user identity amd mfa provider.
type UserMfaToken struct {
	// UserIdentity is the user identity record.
	UserIdentity *UserIdentity

	// MfaProvider is the mfa provider.
	MfaProvider *MfaProvider
}

// MfaConnection contains property of mfa provider for showing to the user.
type MfaConnection struct {
	// Name is the name of connection.
	Name string `bson:"name" json:"name"`

	// Type is the type of provider (otp, sms).
	Type string `bson:"type" json:"type"`

	// Channel is the channel of delivery code.
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
