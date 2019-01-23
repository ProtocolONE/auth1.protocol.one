package models

type (
	ChangePasswordStartForm struct {
		ClientID   string `json:"client_id" form:"client_id" validate:"required"`
		Connection string `json:"connection" form:"connection" validate:"required"`
		Email      string `json:"email" form:"email" validate:"required,email"`
	}

	ChangePasswordVerifyForm struct {
		ClientID       string `form:"client_id" validate:"required"`
		Connection     string `form:"connection" validate:"required"`
		Token          string `form:"token" validate:"required"`
		Password       string `form:"password" validate:"required"`
		PasswordRepeat string `form:"password_repeat" validate:"required"`
	}

	ChangePasswordTokenSource struct {
		Email string
	}
)
