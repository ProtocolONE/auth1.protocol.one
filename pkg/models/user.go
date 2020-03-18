package models

import (
	"time"

	"github.com/globalsign/mgo/bson"
	"go.uber.org/zap/zapcore"
)

// User describes a table for storing the basic properties of the user.
type User struct {
	// ID is the id of user.
	ID bson.ObjectId `bson:"_id" json:"id"`

	// AppID is the id of the application.
	AppID bson.ObjectId `bson:"app_id" json:"app_id"`

	// Email is the email address of the user.
	Email string `bson:"email" json:"email" validate:"required,email"`

	// EmailVerified is status of verification user address.
	EmailVerified bool `bson:"email_verified" json:"email_verified"`

	// PhoneNumber is the phone number of the user.
	PhoneNumber string `bson:"phone_number" json:"phone_number"`

	// PhoneVerified is status of verification user phone.
	PhoneVerified bool `bson:"phone_verified" json:"phone_verified"`

	// Username is the nickname of the user.
	Username string `bson:"username" json:"username"`

	// UniqueUsername is index flag that username must be unique within app.
	UniqueUsername bool `bson:"unique_username" json:"-"`

	// Name is the name of the user. Contains first anf last name.
	Name string `bson:"name" json:"name"`

	// Picture is the avatar of the user.
	Picture string `bson:"picture" json:"picture"`

	// LastIp returns the ip of the last login.
	LastIp string `bson:"last_ip" json:"last_ip"`

	// LastLogin returns the timestamp of the last login.
	LastLogin time.Time `bson:"last_login" json:"last_login"`

	// LoginsCount contains count authorization for the user.
	LoginsCount int `bson:"logins_count" json:"logins_count"`

	// Blocked is status of user blocked.
	Blocked bool `bson:"blocked" json:"blocked"`

	// DeviceID is unique user client identifier
	DeviceID []string `bson:"device_id" json:"device_id"`

	// CreatedAt returns the timestamp of the user creation.
	CreatedAt time.Time `bson:"created_at" json:"created_at"`

	// UpdatedAt returns the timestamp of the last update.
	UpdatedAt time.Time `bson:"updated_at" json:"updated_at"`
}

func (u *User) AddDeviceID(deviceID string) {
	for i := range u.DeviceID {
		if u.DeviceID[i] == deviceID {
			return
		}
	}
	u.DeviceID = append(u.DeviceID, deviceID)
}

// AuthorizeForm contains form fields for requesting a social authorization form.
type AuthorizeForm struct {
	// ClientID is the id of the application.
	ClientID string `query:"client_id" form:"client_id" json:"client_id" validate:"required"`

	// Connection is the name of identity provider (see AppIdentityProvider) and contains name of social network.
	Connection string `query:"connection" form:"connection" json:"connection" validate:"required"`

	// RedirectUri is the url for redirection the user after login.
	RedirectUri string `query:"redirect_uri" form:"redirect_uri" json:"redirect_uri"`

	// State is a data line that the application specified before authorization.
	State string `query:"state" form:"state" json:"state"`
}

// AuthorizeResultForm contains form fields for validation result of social authorization.
type AuthorizeResultForm struct {
	// Code is the oauth2 authorization code for exchange to the tokens.
	Code string `query:"code" form:"code" json:"code" validate:"required"`

	// State is a data line that the application specified before authorization.
	State string `query:"state" form:"state" json:"state" validate:"required"`
}

// AuthorizeResultForm contains the response fields for social authorization page.
type AuthorizeResultResponse struct {
	// Result is the result of social authorization. Result may by `success` or `error`.
	Result string `json:"result"`

	// Payload contains information for further authorization in Auth1.
	// Typically, this is a one-time token to complete the authorization process (see Oauth2LoginSubmitForm).
	Payload interface{} `json:"payload"`
}

type AuthorizeLinkForm struct {
	// Challenge is the code of the oauth2 login challenge. This code to generates of the Hydra service.
	Challenge string `query:"challenge" form:"challenge" json:"challenge" validate:"required"`

	// ClientID is the id of the application.
	ClientID string `query:"client_id" form:"client_id" json:"client_id" validate:"required"`

	// Code is a one-time token created as a result of finding an account with the same mail in the password provider.
	Code string `query:"code" form:"code" json:"code" validate:"required"`

	// The Action determines the type of action that needs to be made on requesting a bunch of accounts.
	// If the `link` is transmitted, then an attempt will be made to bundle a social account with an identifier by
	// login and password. If transferred to `new`, then a new account will be created.
	Action string `query:"action" form:"action" json:"action" validate:"required"`

	// Password is the user's password if he wants to link the social account and with the ID by login and password
	// (if during the authorization process an account containing the same mail as on the social network was found).
	// If linking is not needed, the parameter is not passed or is empty.
	Password string `query:"password" form:"password" json:"password"`
}

// LoginPageForm contains fields for show authorization and registration form.
type LoginPageForm struct {
	// ClientID is the id of the application.
	ClientID string `form:"client_id" query:"client_id"`

	// RedirectUri is the url for redirection the user after login.
	RedirectUri string `form:"redirect_uri" query:"redirect_uri"`

	// State is a data line that the application specified before authorization.
	State string `form:"state" query:"state"`

	// Scope is a list of scopes that the user has taken.
	Scopes string `form:"scopes" query:"scopes"`
}

func (a *User) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("ID", a.ID.String())
	enc.AddString("ApplicationID", a.AppID.String())
	enc.AddString("Email", a.Email)
	enc.AddBool("EmailVerified", a.EmailVerified)
	enc.AddTime("CreatedAt", a.CreatedAt)
	enc.AddTime("UpdatedAt", a.UpdatedAt)

	return nil
}

func (a *AuthorizeForm) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("ClientID", a.ClientID)
	enc.AddString("Name", a.Connection)
	enc.AddString("RedirectUri", a.RedirectUri)
	enc.AddString("State", a.State)

	return nil
}

func (a *AuthorizeResultForm) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("Code", a.Code)
	enc.AddString("State", a.State)

	return nil
}

func (a *AuthorizeLinkForm) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("ClientID", a.ClientID)
	enc.AddString("Code", a.Code)
	enc.AddString("Action", a.Action)
	enc.AddString("Password", "[HIDDEN]")
	enc.AddString("AccessToken", "[HIDDEN]")

	return nil
}
