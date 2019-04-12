package models

import (
	"github.com/globalsign/mgo/bson"
	"go.uber.org/zap/zapcore"
	"time"
)

type User struct {
	ID            bson.ObjectId `bson:"_id" json:"id"`
	AppID         bson.ObjectId `bson:"app_id" json:"app_id"`
	Email         string        `bson:"email" json:"email" validate:"required,email"`
	EmailVerified bool          `bson:"email_verified" json:"email_verified"`
	PhoneNumber   string        `bson:"phone_number" json:"phone_number"`
	PhoneVerified bool          `bson:"phone_verified" json:"phone_verified"`
	Username      string        `bson:"username" json:"username"`
	Name          string        `bson:"name" json:"name"`
	Picture       string        `bson:"picture" json:"picture"`
	LastIp        string        `bson:"last_ip" json:"last_ip"`
	LastLogin     time.Time     `bson:"last_login" json:"last_login"`
	LoginsCount   int           `bson:"logins_count" json:"logins_count"`
	Blocked       bool          `bson:"blocked" json:"blocked"`
	CreatedAt     time.Time     `bson:"created_at" json:"created_at"`
	UpdatedAt     time.Time     `bson:"updated_at" json:"updated_at"`
}

type SignUpForm struct {
	ClientID    string `form:"client_id" json:"client_id" validate:"required"`
	Connection  string `form:"connection" json:"connection" validate:"required"`
	Email       string `form:"email" json:"email" validate:"required,email"`
	Password    string `form:"password" json:"password" validate:"required"`
	RedirectUri string `query:"redirect_uri" form:"redirect_uri" json:"redirect_uri"`
}

type AuthorizeForm struct {
	ClientID    string `query:"client_id" form:"client_id" json:"client_id" validate:"required"`
	Connection  string `query:"connection" form:"connection" json:"connection" validate:"required"`
	RedirectUri string `query:"redirect_uri" form:"redirect_uri" json:"redirect_uri"`
	State       string `query:"state" form:"state" json:"state"`
}

type AuthorizeResultForm struct {
	Code  string `query:"code" form:"code" json:"code" validate:"required"`
	State string `query:"state" form:"state" json:"state" validate:"required"`
}

type AuthorizeResultResponse struct {
	Result  string      `json:"result"`
	Payload interface{} `json:"payload"`
}

type AuthorizeLinkForm struct {
	Challenge string `query:"challenge" form:"challenge" json:"challenge" validate:"required"`
	ClientID  string `query:"client_id" form:"client_id" json:"client_id" validate:"required"`
	Code      string `query:"code" form:"code" json:"code" validate:"required"`
	Action    string `query:"action" form:"action" json:"action" validate:"required"`
	Password  string `query:"password" form:"password" json:"password"`
}

type LoginForm struct {
	ClientID    string `form:"client_id" validate:"required" json:"client_id"`
	Email       string `form:"email" validate:"required,email" json:"email"`
	Password    string `form:"password" validate:"required" json:"password"`
	Captcha     string `form:"captcha" json:"captcha"`
	RedirectUri string `form:"redirect_uri" query:"redirect_uri" json:"redirect_uri"`
}

type LoginPageForm struct {
	ClientID    string `form:"client_id" query:"client_id"`
	RedirectUri string `form:"redirect_uri" query:"redirect_uri"`
	State       string `form:"state" query:"state"`
	Scopes      string `form:"scopes" query:"scopes"`
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

func (a *LoginForm) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("ClientID", a.ClientID)
	enc.AddString("Email", a.Email)
	enc.AddString("Password", "[HIDDEN]")
	enc.AddString("Captcha", a.Captcha)

	return nil
}

func (a *SignUpForm) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("ClientID", a.ClientID)
	enc.AddString("Name", a.Connection)
	enc.AddString("Email", a.Email)
	enc.AddString("Password", "[HIDDEN]")

	return nil
}
