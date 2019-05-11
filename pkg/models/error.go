package models

var (
	ErrorUnknownError             = "Unknown error"
	ErrorInvalidRequestParameters = "Invalid request parameters"
	ErrorRequiredField            = "This is required field"
	ErrorAddAuthLog               = "Unable to add auth log"
	ErrorCreateCookie             = "Unable to create cookie"
	ErrorCreateUser               = "Unable to create user"
	ErrorUpdateUser               = "Unable to update user"
	ErrorCreateUserIdentity       = "Unable to create user identity"
	ErrorLoginIncorrect           = "Login is incorrect"
	ErrorCryptPassword            = "Unable to crypt password"
	ErrorUnableChangePassword     = "Unable to change password"
	ErrorUnableCreateOttSettings  = "Unable create ott settings"
	ErrorPasswordIncorrect        = "Password is incorrect"
	ErrorPasswordRepeat           = "Password repeat is not equal to password"
	ErrorUnableValidatePassword   = "Unable to validate password"
	ErrorClientIdIncorrect        = "Client ID is incorrect"
	ErrorConnectionIncorrect      = "Name is incorrect"
	ErrorCannotCreateToken        = "Cannot create token"
	ErrorCannotUseToken           = "Cannot use this token"
	ErrorRedirectUriIncorrect     = "Redirect URI is incorrect"
	ErrorCaptchaRequired          = "Captcha required"
	ErrorCaptchaIncorrect         = "Captcha is incorrect"
	ErrorAuthTemporaryLocked      = "Temporary locked"
	ErrorProviderIdIncorrect      = "Provider ID is incorrect"
	ErrorGetSocialData            = "Unable to load social data"
	ErrorGetSocialSettings        = "Unable to load social settings"
	ErrorMfaRequired              = "MFA required"
	ErrorMfaClientAdd             = "Unable to add MFA"
	ErrorMfaCodeInvalid           = "Invalid MFA code"
	ErrorLoginChallenge           = "Invalid login challenge"
)

// ErrorInterface defines basic methods for application errors.
type ErrorInterface interface {
	// GetHttpCode return the http code of the error.
	GetHttpCode() int

	// GetCode return code of the error.
	GetCode() string

	// GetMessage return message of the error.
	GetMessage() string

	// Error return original error.
	Error() string
}

// GeneralError is the basic type of application errors that are used in managers and
// processed in controllers to generate http responses.
type GeneralError struct {
	// Code is the error code.
	Code string `json:"error,omitempty"`

	// HttpCode is the code for http response.
	HttpCode int `json:"-"`

	// Message is the human-readable string of error message.
	Message string `json:"error_message,omitempty"`

	// Error contains original error.
	Err error `json:"-"`
}

func (e *GeneralError) Error() string {
	return e.Message
}
