package models

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
