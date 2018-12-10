package models

type MfaChallengeForm struct {
	ClientId   string `json:"client_id" form:"client_id" validate:"required"`
	Connection string `json:"connection" form:"connection" validate:"required"`
	Token      string `json:"mfa_token" form:"mfa_token" validate:"required"`
	Type       string `json:"challenge_type" form:"challenge_type"`
}
