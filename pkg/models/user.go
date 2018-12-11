package models

type User struct {
	CreatedAt     string `json:"created_at,omitempty"`
	Email         string `json:"email,omitempty" validate:"required,email" form:"email"`
	EmailVerified bool   `json:"email_verified,omitempty"`
	ID            string `json:"id,omitempty"`
	UpdatedAt     string `json:"updated_at,omitempty"`
}
