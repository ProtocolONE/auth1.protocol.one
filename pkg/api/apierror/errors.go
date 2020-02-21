package apierror

import (
	"fmt"
	"net/http"
)

const (
	ErrorPrefix   = "errors.one.protocol.auth1."
	ServicePrefix = "AU"
)

var (
	unknown            = New(1000, "unknown", http.StatusInternalServerError)
	invalidRequest     = New(1001, "invalid_request", http.StatusBadRequest)
	invalidParameters  = New(1002, "invalid_parameters", http.StatusBadRequest)
	InvalidChallenge   = New(1003, "invalid_challenge", http.StatusBadRequest).WithParam("challenge")
	InvalidToken       = New(1004, "invalid_token", http.StatusBadRequest).WithParam("token")
	InvalidClient      = New(1005, "invalid_client", http.StatusBadRequest)
	EmailNotFound      = New(1006, "email_not_found", http.StatusBadRequest).WithParam("email")
	InvalidCredentials = New(1007, "invalid_credentials", http.StatusBadRequest)
	UsernameTaken      = New(1008, "username_already_exists", http.StatusBadRequest).WithParam("username")
	WeakPassword       = New(1009, "password_does_not_meet_policy", http.StatusBadRequest).WithParam("password")
	EmailRegistered    = New(1010, "email_already_registered", http.StatusBadRequest).WithParam("email")
	MissingCSRFToken   = New(1011, "missing_csrf_token", http.StatusBadRequest).WithParam("x-xsrf-token")
	InvalidCSRFToken   = New(1012, "invalid_csrf_token", http.StatusForbidden).WithParam("x-xsrf-token")
	MethodNotAllowed   = New(1013, "method_not_allowed", http.StatusMethodNotAllowed)
	NotFound           = New(1014, "not_found", http.StatusNotFound)
	CaptchaRequired    = New(1015, "captcha_required", http.StatusForbidden)
	UnknownCaptchaType = New(1016, "unknown_captcha_type", http.StatusBadRequest)
	TokenOutdated      = New(1017, "token_outdated", http.StatusForbidden)
)

func New(code int, message string, status int) *APIError {
	return NewAPIError(fmt.Sprintf("%s-%d", ServicePrefix, code), ErrorPrefix+message, status)
}

func Unknown(err error) *APIError {
	return unknown
}

func InvalidRequest(err error) *APIError {
	return invalidRequest
}

func InvalidParameters(err error) *APIError {
	return invalidParameters
}
