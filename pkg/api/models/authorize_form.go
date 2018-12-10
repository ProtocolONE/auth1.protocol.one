package models

type AuthorizeForm struct {
	ClientId    string `json:"client_id" form:"client_id" validate:"required"`
	Connection  string `json:"connection" form:"connection" validate:"required"`
	RedirectUri string `json:"redirect_uri" form:"redirect_uri" validate:"required"`
	State       string `json:"state" form:"state" validate:"required"`
}
