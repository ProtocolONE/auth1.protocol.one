package models

type ChangePasswordStartForm struct {
	ClientId   string `json:"client_id" form:"client_id" validate:"required"`
	Connection string `json:"connection" form:"connection" validate:"required"`
	Email      string `json:"email" form:"email" validate:"required,email"`
}
