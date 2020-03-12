package service

import (
	"github.com/go-openapi/runtime"
	"github.com/ory/hydra/sdk/go/hydra/client/admin"
)

// HydraAdminApi describes of methods for the Hydra administration api.
// See the documentation for the methods in Hydra - https://www.ory.sh/docs/next/hydra/sdk/api
type HydraAdminApi interface {
	// CreateOAuth2Client creates an o auth 2 0 client.
	CreateOAuth2Client(*admin.CreateOAuth2ClientParams) (*admin.CreateOAuth2ClientCreated, error)

	// GetOAuth2Client gets an o auth 2 0 client.
	GetOAuth2Client(*admin.GetOAuth2ClientParams) (*admin.GetOAuth2ClientOK, error)

	// UpdateOAuth2Client updates an o auth 2 0 client.
	UpdateOAuth2Client(*admin.UpdateOAuth2ClientParams) (*admin.UpdateOAuth2ClientOK, error)

	// GetLoginRequest gets an login request.
	GetLoginRequest(*admin.GetLoginRequestParams) (*admin.GetLoginRequestOK, error)

	// AcceptLoginRequest accepts an login request.
	AcceptLoginRequest(*admin.AcceptLoginRequestParams) (*admin.AcceptLoginRequestOK, error)

	// GetConsentRequest gets consent request information.
	GetConsentRequest(*admin.GetConsentRequestParams) (*admin.GetConsentRequestOK, error)

	// AcceptConsentRequest accepts an consent request.
	AcceptConsentRequest(*admin.AcceptConsentRequestParams) (*admin.AcceptConsentRequestOK, error)

	// IntrospectOAuth2Token introspects o auth2 tokens.
	IntrospectOAuth2Token(*admin.IntrospectOAuth2TokenParams, runtime.ClientAuthInfoWriter) (*admin.IntrospectOAuth2TokenOK, error)

	// ListSubjectConsentSessions lists all consent sessions of a subject
	ListSubjectConsentSessions(params *admin.ListSubjectConsentSessionsParams) (*admin.ListSubjectConsentSessionsOK, error)

	// RevokeConsentSessions revokes consent sessions of a subject for a specific o auth 2 0 client
	RevokeConsentSessions(params *admin.RevokeConsentSessionsParams) (*admin.RevokeConsentSessionsNoContent, error)

	// RevokeAuthenticationSession invalidates a user s authentication session
	RevokeAuthenticationSession(params *admin.RevokeAuthenticationSessionParams) (*admin.RevokeAuthenticationSessionNoContent, error)
}
