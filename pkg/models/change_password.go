package models

import "go.uber.org/zap/zapcore"

// ChangePasswordForm contains form fields for requesting a password change.
type ChangePasswordForm struct {
	// ClientID is the application id
	ClientID string `json:"client_id" query:"client_id" validate:"required"`
}

func (a *ChangePasswordForm) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("ClientID", a.ClientID)

	return nil
}

// ChangePasswordStartForm contains the form fields for starting an operation for changing the password.
type ChangePasswordStartForm struct {
	// ClientID is the application id
	ClientID string `json:"client_id" form:"client_id" validate:"required"`

	// Email is the email address of the user to which the account is registered.
	Email string `json:"email" form:"email" validate:"required,email"`
}

// ChangePasswordVerifyForm contains form fields for completing a password change.
type ChangePasswordVerifyForm struct {
	// ClientID is the application id
	ClientID string `form:"client_id" json:"client_id" validate:"required"`

	// Token is a one-time token from a password change letter.
	Token string `form:"token" json:"token" validate:"required"`

	// Password is a new user password.
	Password string `form:"password" json:"password" validate:"required"`

	// PasswordRepeat is a confirmation of a new user password.
	PasswordRepeat string `form:"password_repeat" json:"password_repeat" validate:"required"`
}

type ChangePasswordTokenSource struct {
	Email string
}

func (a *ChangePasswordStartForm) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("ClientID", a.ClientID)
	enc.AddString("Email", a.Email)

	return nil
}

func (a *ChangePasswordVerifyForm) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("ClientID", a.ClientID)
	enc.AddString("Token", "[HIDDEN]")
	enc.AddString("Password", "[HIDDEN]")
	enc.AddString("PasswordRepeat", "[HIDDEN]")

	return nil
}
