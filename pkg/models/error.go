package models

type (
	ErrorInterface interface {
		GetCode() string
		GetMessage() string
	}

	CommonError struct {
		Code    string `json:"error,omitempty"`
		Message string `json:"error_message,omitempty"`
	}
)

var (
	ErrorUnknownError             = "Unknown error"
	ErrorInvalidRequestParameters = "Invalid request parameters"
	ErrorRequiredField            = "This is required field"
	ErrorAddAuthLog               = "Unable to add auth log"
	ErrorCreateCookie             = "Unable to create cookie"
	ErrorCreateUser               = "Unable to create user"
	ErrorCreateUserIdentity       = "Unable to create user identity"
	ErrorLoginIncorrect           = "Login is incorrect"
	ErrorCryptPassword            = "Unable to crypt password"
	ErrorUnableChangePassword     = "Unable to change password"
	ErrorUnableCreateOttSettings  = "Unable create ott settings"
	ErrorPasswordIncorrect        = "Password is incorrect"
	ErrorPasswordRepeat           = "Password repeat is not equal to password"
	ErrorUnableValidatePassword   = "Unable to validate password"
	ErrorClientIdIncorrect        = "Client ID is incorrect"
	ErrorConnectionIncorrect      = "Connection is incorrect"
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
)

func (m *CommonError) Error() string {
	return m.Message
}

func (m *CommonError) GetCode() string {
	return m.Code
}

func (m *CommonError) GetMessage() string {
	return m.Message
}
