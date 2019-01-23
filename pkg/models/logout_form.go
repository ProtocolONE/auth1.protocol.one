package models

type LogoutForm struct {
	ClientId    string `query:"client_id" form:"client_id" validate:"required"`
	RedirectUri string `query:"redirect_uri" form:"redirect_uri" validate:"required"`
}
