package models

import "go.uber.org/zap/zapcore"

type ChangePasswordForm struct {
	ClientID string `json:"client_id" query:"client_id" validate:"required"`
}

func (a *ChangePasswordForm) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("ClientID", a.ClientID)

	return nil
}

type ChangePasswordStartForm struct {
	ClientID   string `json:"client_id" form:"client_id" validate:"required"`
	Connection string `json:"connection" form:"connection"`
	Email      string `json:"email" form:"email" validate:"required,email"`
}

type ChangePasswordVerifyForm struct {
	ClientID       string `form:"client_id" json:"client_id" validate:"required"`
	Connection     string `form:"connection" json:"connection"`
	Token          string `form:"token" json:"token" validate:"required"`
	Password       string `form:"password" json:"password" validate:"required"`
	PasswordRepeat string `form:"password_repeat" json:"password_repeat" validate:"required"`
}

type ChangePasswordTokenSource struct {
	Email string
}

func (a *ChangePasswordStartForm) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("ClientID", a.ClientID)
	enc.AddString("Name", a.Connection)
	enc.AddString("Email", a.Email)

	return nil
}

func (a *ChangePasswordVerifyForm) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("ClientID", a.ClientID)
	enc.AddString("Name", a.Connection)
	enc.AddString("Token", "[HIDDEN]")
	enc.AddString("Password", "[HIDDEN]")
	enc.AddString("PasswordRepeat", "[HIDDEN]")

	return nil
}
