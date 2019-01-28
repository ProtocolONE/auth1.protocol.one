package models

type LogoutForm struct {
	ClientId    string `query:"client_id" form:"client_id" json:"client_id" validate:"required"`
	RedirectUri string `query:"redirect_uri" form:"redirect_uri" json:"redirect_uri" validate:"required"`
}
