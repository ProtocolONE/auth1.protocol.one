package models

type AuthorizeResultForm struct {
	ClientId   string `json:"client_id" form:"client_id" validate:"required"`
	Connection string `json:"connection" form:"connection" validate:"required"`
	OTT        string `json:"auth_one_ott" form:"auth_one_ott" validate:"required"`
	WsUrl      string `json:"ws_url" form:"ws_url"`
}
