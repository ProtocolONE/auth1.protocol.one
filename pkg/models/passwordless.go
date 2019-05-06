package models

import "go.uber.org/zap/zapcore"

type PasswordLessStartForm struct {
	ClientId   string `json:"client_id" form:"client_id" validate:"required"`
	Connection string `json:"connection" form:"connection" validate:"required"`
}

type PasswordLessVerifyForm struct {
	ClientId   string `json:"client_id" form:"client_id" validate:"required"`
	Connection string `json:"connection" form:"connection" validate:"required"`
	Code       string `json:"verification_code" form:"verification_code" validate:"required"`
	Token      string `json:"token" form:"token" validate:"required"`
}

func (m *PasswordLessStartForm) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("ClientId", m.ClientId)
	enc.AddString("Name", m.Connection)

	return nil
}

func (m *PasswordLessVerifyForm) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("ClientId", m.ClientId)
	enc.AddString("Name", m.Connection)
	enc.AddString("Code", m.Code)
	enc.AddString("Token", m.Token)

	return nil
}
