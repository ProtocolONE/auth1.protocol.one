package models

type LogoutForm struct {
	ClientId    string `json:"client_id" form:"client_id" validate:"required"`
	RedirectUri string `json:"redirect_uri" form:"redirect_uri" validate:"required"`
}
