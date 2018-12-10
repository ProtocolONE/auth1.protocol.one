package models

type PasswordLessStartForm struct {
	ClientId   string `json:"client_id" form:"client_id" validate:"required"`
	Connection string `json:"connection" form:"connection" validate:"required"`
}
