package api

const (
	BadRequiredCodeField  = `field:%s`
	BadRequiredCodeCommon = `invalid_argument`
	MFARequiredCode       = `mfa_required`
	CaptchaRequiredCode   = `captcha_required`
	TemporaryLockedCode   = `login_temporary_locked`
	InvalidAuthTokenCode  = `auth_token_invalid`
	UnknownErrorCode      = `unknown_error`
)
