package models

import (
	hydra_models "github.com/ory/hydra/sdk/go/hydra/models"
	"go.uber.org/zap/zapcore"
)

// Oauth2LoginForm contains form fields for requesting a login form.
type Oauth2LoginForm struct {
	// Challenge is the code of the oauth2 login challenge. This code to generates of the Hydra service.
	Challenge string `query:"login_challenge" form:"login_challenge" validate:"required"`
}

func (a *Oauth2LoginForm) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("Challenge", a.Challenge)

	return nil
}

// Oauth2LoginSubmitForm contains form fields for submit login form.
type Oauth2LoginSubmitForm struct {
	// Challenge is the code of the oauth2 login challenge. This code to generates of the Hydra service.
	Challenge string `query:"challenge" form:"challenge" validate:"required"`

	// Email is the email address of user for login request.
	Email string `query:"email" form:"email"`

	// Password is the password string of user for login request.
	Password string `query:"password" form:"password"`

	// PreviousLogin is the previous user login, which was detected in the authorization session and
	// the user selected login through it (without asking for a password).
	PreviousLogin string `query:"previous_login" form:"previous_login"`

	// Token is the one-time token for authorize user without password.
	Token string `query:"token" form:"token"`

	// Remember is the option for the save user session in the cookie.
	Remember bool `query:"remember" form:"remember"`
}

// Oauth2ConsentForm contains form fields for request of consent.
type Oauth2ConsentForm struct {
	// Challenge is the code of the oauth2 consent challenge. This code to generates of the Hydra service.
	Challenge string `query:"consent_challenge" form:"consent_challenge" validate:"required"`
}

func (a *Oauth2ConsentForm) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("Challenge", a.Challenge)

	return nil
}

// Oauth2ConsentSubmitForm contains form fields for submit consent form.
type Oauth2ConsentSubmitForm struct {
	// Challenge is the code of the oauth2 consent challenge. This code to generates of the Hydra service.
	Challenge string `query:"challenge" form:"challenge" validate:"required"`

	// Scope is a list of scopes that the user has taken.
	Scope []string `query:"scope" form:"scope" validate:"required"`
}

func (a *Oauth2LoginSubmitForm) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("Challenge", a.Challenge)
	enc.AddString("Email", a.Email)
	enc.AddString("Password", "[HIDDEN]")

	return nil
}

// Oauth2IntrospectForm contains form fields for request of the introspect access token.
type Oauth2IntrospectForm struct {
	// ClientID is the id of the application.
	ClientID string `query:"client_id" form:"client_id" validate:"required"`

	// Secret is the authorization secret of the application.
	Secret string `query:"secret" form:"secret" validate:"required"`

	// Token is the access token.
	Token string `query:"token" form:"token" validate:"required"`
}

func (a *Oauth2IntrospectForm) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("ClientID", a.ClientID)
	enc.AddString("Token", a.Token)
	enc.AddString("Secret", "[HIDDEN]")

	return nil
}

// Oauth2TokenIntrospection contains an access token's session data as specified by IETF RFC 7662, see:
//
// https://tools.ietf.org/html/rfc7662
type Oauth2TokenIntrospection struct {
	*hydra_models.Introspection
}

// Oauth2SignUpForm contains form fields for request signup form.
type Oauth2SignUpForm struct {
	// Challenge is the code of the oauth2 login challenge. This code to generates of the Hydra service.
	Challenge string `query:"challenge" form:"challenge" validate:"required"`

	// Email is the email address of user for the registration.
	Email string `query:"email" form:"email" validate:"required"`

	// Password is the password string of user for the registration.
	Password string `query:"password" form:"password" validate:"required"`

	// Remember is the option for the save user session in the cookie.
	Remember bool `query:"remember" form:"remember"`
}

func (a *Oauth2SignUpForm) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("Challenge", a.Challenge)
	enc.AddString("Email", a.Email)
	enc.AddString("Password", "[HIDDEN]")

	return nil
}

// Oauth2CallBackForm contains form fields for request oauth2 callback process.
type Oauth2CallBackForm struct {
	// Code is the oauth2 authorization code for exchange to the tokens.
	Code string `query:"code" form:"code" validate:"required"`

	// State is a data line that the application specified before registration or authorization.
	State string `query:"state" form:"state" validate:"required"`

	// Scope is a list of scopes that the user has taken.
	Scope string `query:"scope" form:"scope" validate:"required"`
}

func (a *Oauth2CallBackForm) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("Code", a.Code)
	enc.AddString("State", a.State)
	enc.AddString("Scope", a.Scope)

	return nil
}

// Oauth2CallBackResponse contains the response fields for the callback result page.
type Oauth2CallBackResponse struct {
	// Success is the result of the exchange of code. If true, the code was successfully exchanged for tokens.
	Success bool `json:"success"`

	// ErrorMessage is the human-readable string with error message if code was unsuccessfully exchanged.
	ErrorMessage string `json:"error_message,omitempty"`

	// AccessToken is the access token for authorize user in the application.
	AccessToken string `json:"access_token,omitempty"`

	// IdToken is the openid token for authorize user in the application.
	IdToken string `json:"id_token,omitempty"`

	// ExpiresIn is the timestamp of expiration the token.
	ExpiresIn int `json:"expires_in,omitempty"`
}

// Oauth2LogoutForm contains form fields for requesting a logout form.
type Oauth2LogoutForm struct {
	// RedirectUri is the url for redirection the user after logout process.
	RedirectUri string `query:"redirect_uri"`
}
