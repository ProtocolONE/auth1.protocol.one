package models

import (
	"go.uber.org/zap/zapcore"
)

type Oauth2LoginForm struct {
	Challenge string `query:"login_challenge" form:"login_challenge" validate:"required"`
}

func (a *Oauth2LoginForm) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("Challenge", a.Challenge)

	return nil
}

type Oauth2LoginSubmitForm struct {
	Challenge     string `query:"challenge" form:"challenge" validate:"required"`
	Email         string `query:"email" form:"email"`
	Password      string `query:"password" form:"password"`
	PreviousLogin string `query:"previous_login" form:"previous_login"`
	Token         string `query:"token" form:"token"`
	Remember      bool   `query:"remember" form:"remember"`
}

type Oauth2ConsentForm struct {
	Challenge string `query:"consent_challenge" form:"consent_challenge" validate:"required"`
}

func (a *Oauth2ConsentForm) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("Challenge", a.Challenge)

	return nil
}

type Oauth2ConsentSubmitForm struct {
	Challenge string   `query:"challenge" form:"challenge" validate:"required"`
	Scope     []string `query:"scope" form:"scope" validate:"required"`
}

func (a *Oauth2LoginSubmitForm) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("Challenge", a.Challenge)
	enc.AddString("Email", a.Email)
	enc.AddString("Password", "[HIDDEN]")

	return nil
}

type Oauth2IntrospectForm struct {
	ClientID string `query:"client_id" form:"client_id" validate:"required"`
	Secret   string `query:"secret" form:"secret" validate:"required"`
	Token    string `query:"token" form:"token" validate:"required"`
}

func (a *Oauth2IntrospectForm) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("ClientID", a.ClientID)
	enc.AddString("Token", a.Token)
	enc.AddString("Secret", "[HIDDEN]")

	return nil
}

type Oauth2TokenIntrospection struct {
	// Active is a boolean indicator of whether or not the presented token
	// is currently active.  The specifics of a token's "active" state
	// will vary depending on the implementation of the authorization
	// server and the information it keeps about its tokens, but a "true"
	// value return for the "active" property will generally indicate
	// that a given token has been issued by this authorization server,
	// has not been revoked by the resource owner, and is within its
	// given time window of validity (e.g., after its issuance time and
	// before its expiration time).
	// Required: true
	Active *bool `json:"active"`

	// Audience contains a list of the token's intended audiences.
	Audience []string `json:"aud"`

	// ClientID is aclient identifier for the OAuth 2.0 client that
	// requested this token.
	ClientID string `json:"client_id,omitempty"`

	// Expires at is an integer timestamp, measured in the number of seconds
	// since January 1 1970 UTC, indicating when this token will expire.
	ExpiresAt int64 `json:"exp,omitempty"`

	// Extra is arbitrary data set by the session.
	Extra map[string]interface{} `json:"ext,omitempty"`

	// Issued at is an integer timestamp, measured in the number of seconds
	// since January 1 1970 UTC, indicating when this token was
	// originally issued.
	IssuedAt int64 `json:"iat,omitempty"`

	// IssuerURL is a string representing the issuer of this token
	Issuer string `json:"iss,omitempty"`

	// NotBefore is an integer timestamp, measured in the number of seconds
	// since January 1 1970 UTC, indicating when this token is not to be
	// used before.
	NotBefore int64 `json:"nbf,omitempty"`

	// ObfuscatedSubject is set when the subject identifier algorithm was set to "pairwise" during authorization.
	// It is the `sub` value of the ID Token that was issued.
	ObfuscatedSubject string `json:"obfuscated_subject,omitempty"`

	// Scope is a JSON string containing a space-separated list of
	// scopes associated with this token.
	Scope string `json:"scope,omitempty"`

	// Subject of the token, as defined in JWT [RFC7519].
	// Usually a machine-readable identifier of the resource owner who
	// authorized this token.
	Subject string `json:"sub,omitempty"`

	// TokenType is the introspected token's type, for example `access_token` or `refresh_token`.
	TokenType string `json:"token_type,omitempty"`

	// Username is a human-readable identifier for the resource owner who
	// authorized this token.
	Username string `json:"username,omitempty"`
}

type Oauth2SignUpForm struct {
	Challenge string `query:"challenge" form:"challenge" validate:"required"`
	Email     string `query:"email" form:"email" validate:"required"`
	Password  string `query:"password" form:"password" validate:"required"`
	Remember  bool   `query:"remember" form:"remember"`
}

func (a *Oauth2SignUpForm) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("Challenge", a.Challenge)
	enc.AddString("Email", a.Email)
	enc.AddString("Password", "[HIDDEN]")

	return nil
}

type Oauth2CallBackForm struct {
	Code  string `query:"code" form:"code" validate:"required"`
	State string `query:"state" form:"state" validate:"required"`
	Scope string `query:"scope" form:"scope" validate:"required"`
}

func (a *Oauth2CallBackForm) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("Code", a.Code)
	enc.AddString("State", a.State)
	enc.AddString("Scope", a.Scope)

	return nil
}

type Oauth2CallBackResponse struct {
	Success      bool   `json:"success"`
	ErrorMessage string `json:"error_message,omitempty"`
	AccessToken  string `json:"access_token,omitempty"`
	IdToken      string `json:"id_token,omitempty"`
	ExpiresIn    int    `json:"expires_in,omitempty"`
}

type Oauth2LogoutForm struct {
	RedirectUri string `query:"redirect_uri"`
}
