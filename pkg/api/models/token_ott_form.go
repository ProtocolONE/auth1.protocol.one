package models

type TokenOttForm struct {
	ClientId string `json:"client_id" form:"client_id" validate:"required"`
	Token    string `json:"token" form:"token" validate:"required"`
}
