package models

type MfaAddForm struct {
	ClientId    string `json:"client_id" form:"client_id" validate:"required"`
	Connection  string `json:"connection" form:"connection" validate:"required"`
	Types       string `json:"authenticator_types" form:"authenticator_types" validate:"required"`
	Channel     string `json:"oob_channel" form:"oob_channel"`
	PhoneNumber string `json:"phone_number" form:"phone_number"`
}
