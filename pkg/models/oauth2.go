package models

import (
	"github.com/ory/hydra/sdk/go/hydra/swagger"
	"go.uber.org/zap/zapcore"
)

type Oauth2LoginForm struct {
	Challenge string `query:"login_challenge" form:"login_challenge" validate:"required"`
}

func (a *Oauth2LoginForm) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("Challenge", a.Challenge)

	return nil
}

type Oauth2LoginSubmitForm struct {
	Csrf          string `query:"csrf" form:"csrf" validate:"required"`
	Challenge     string `query:"challenge" form:"challenge" validate:"required"`
	Email         string `query:"email" form:"email"`
	Password      string `query:"password" form:"password"`
	PreviousLogin string `query:"previous_login" form:"previous_login"`
	Remember      bool   `query:"remember"`
}

type Oauth2ConsentForm struct {
	Challenge string `query:"consent_challenge" form:"consent_challenge" validate:"required"`
}

func (a *Oauth2ConsentForm) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("Challenge", a.Challenge)

	return nil
}

type Oauth2ConsentSubmitForm struct {
	Csrf      string   `query:"csrf" form:"csrf" validate:"required"`
	Challenge string   `query:"challenge" form:"challenge" validate:"required"`
	Scope     []string `query:"scope" form:"scope" validate:"required"`
}

func (a *Oauth2LoginSubmitForm) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("Challenge", a.Challenge)
	enc.AddString("Email", a.Email)
	enc.AddString("Password", "[HIDDEN]")
	enc.AddString("Csrf", a.Csrf)

	return nil
}

type Oauth2IntrospectForm struct {
	ClientID string `query:"client_id" form:"client_id" validate:"required"`
	Secret   string `query:"secret" form:"secret" validate:"required"`
	Token    string `query:"token" form:"token" validate:"required"`
}

func (a *Oauth2IntrospectForm) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("ClientID", a.ClientID)
	enc.AddString("Token", a.Token)
	enc.AddString("Secret", "[HIDDEN]")

	return nil
}

type Oauth2TokenIntrospection struct {
	*swagger.OAuth2TokenIntrospection
}

type Oauth2SignUpForm struct {
	Csrf      string `query:"csrf" form:"csrf" validate:"required"`
	Challenge string `query:"challenge" form:"challenge" validate:"required"`
	Email     string `query:"email" form:"email" validate:"required"`
	Password  string `query:"password" form:"password" validate:"required"`
	Remember  bool   `query:"remember"`
}

func (a *Oauth2SignUpForm) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("Challenge", a.Challenge)
	enc.AddString("Email", a.Email)
	enc.AddString("Password", "[HIDDEN]")
	enc.AddString("Csrf", a.Csrf)

	return nil
}

type Oauth2CallBackForm struct {
	Code  string `query:"code" form:"code" validate:"required"`
	State string `query:"state" form:"state" validate:"required"`
	Scope string `query:"scope" form:"scope" validate:"required"`
}

func (a *Oauth2CallBackForm) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("Code", a.Code)
	enc.AddString("State", a.State)
	enc.AddString("Scope", a.Scope)

	return nil
}

type Oauth2CallBackResponse struct {
	Success      bool   `json:"success"`
	ErrorMessage string `json:"error_message,omitempty"`
	AccessToken  string `json:"access_token,omitempty"`
	IdToken      string `json:"id_token,omitempty"`
	ExpiresIn    int    `json:"expires_in,omitempty"`
}

type Oauth2LogoutForm struct {
	RedirectUri string `query:"redirect_uri"`
}
