package models

type JWTToken struct {
	AccessToken  string `json:"access_token,omitempty"`
	ExpiresIn    int32  `json:"expires_in,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
}
