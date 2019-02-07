package models

import "go.uber.org/zap/zapcore"

type OauthLoginForm struct {
	Challenge string `query:"login_challenge" form:"login_challenge" validate:"required"`
}

type OauthLoginSubmitForm struct {
	Csrf      string `query:"_csrf" form:"_csrf" validate:"required"`
	Challenge string `query:"challenge" form:"challenge" validate:"required"`
	Email     string `query:"email" form:"email" validate:"required"`
	Password  string `query:"password" form:"password" validate:"required"`
	Remember  bool   `query:"remember" form:"remember"`
}

type OauthConsentForm struct {
	Challenge string `query:"consent_challenge" form:"consent_challenge" validate:"required"`
}

type OauthConsentSubmitForm struct {
	Csrf      string   `query:"_csrf" form:"_csrf" validate:"required"`
	Challenge string   `query:"challenge" form:"challenge" validate:"required"`
	Scope     []string `query:"scope" form:"scope" validate:"required"`
}

type OauthCallbackForm struct {
	Code  string `query:"code" form:"code" validate:"required"`
	State string `query:"state" form:"state" validate:"required"`
	Scope string `query:"scope" form:"scope" validate:"false"`
}

func (a *OauthLoginSubmitForm) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("Challenge", a.Challenge)
	enc.AddString("Email", a.Email)
	enc.AddString("Password", "[HIDDEN]")
	enc.AddString("Csrf", a.Csrf)

	return nil
}
