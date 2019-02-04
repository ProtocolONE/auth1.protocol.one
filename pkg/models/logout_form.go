package models

import "go.uber.org/zap/zapcore"

type LogoutForm struct {
	ClientId    string `query:"client_id" form:"client_id" json:"client_id" validate:"required"`
	RedirectUri string `query:"redirect_uri" form:"redirect_uri" json:"redirect_uri"`
}

func (a *LogoutForm) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("ClientID", a.ClientId)
	enc.AddString("RedirectUri", a.RedirectUri)

	return nil
}
