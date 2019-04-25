package service

import (
	"github.com/go-openapi/runtime"
	"github.com/ory/hydra/sdk/go/hydra/client/admin"
)

type HydraAdminApi interface {
	CreateOAuth2Client(*admin.CreateOAuth2ClientParams) (*admin.CreateOAuth2ClientCreated, error)
	GetOAuth2Client(*admin.GetOAuth2ClientParams) (*admin.GetOAuth2ClientOK, error)
	UpdateOAuth2Client(*admin.UpdateOAuth2ClientParams) (*admin.UpdateOAuth2ClientOK, error)
	GetLoginRequest(*admin.GetLoginRequestParams) (*admin.GetLoginRequestOK, error)
	AcceptLoginRequest(*admin.AcceptLoginRequestParams) (*admin.AcceptLoginRequestOK, error)
	GetConsentRequest(*admin.GetConsentRequestParams) (*admin.GetConsentRequestOK, error)
	AcceptConsentRequest(*admin.AcceptConsentRequestParams) (*admin.AcceptConsentRequestOK, error)
	IntrospectOAuth2Token(*admin.IntrospectOAuth2TokenParams, runtime.ClientAuthInfoWriter) (*admin.IntrospectOAuth2TokenOK, error)
}
