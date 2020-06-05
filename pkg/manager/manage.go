package manager

import (
	"context"
	"fmt"
	"time"

	"github.com/ProtocolONE/auth1.protocol.one/internal/domain/entity"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/database"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/helper"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/models"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/service"
	"github.com/globalsign/mgo/bson"
	"github.com/labstack/echo/v4"
	"github.com/ory/hydra-client-go/client/admin"
	hydra_models "github.com/ory/hydra-client-go/models"
	"github.com/pkg/errors"
)

type ManageManager struct {
	mfaService              service.MfaServiceInterface
	identityProviderService service.AppIdentityProviderServiceInterface
	r                       service.InternalRegistry
}

func NewManageManager(db database.MgoSession, r service.InternalRegistry) *ManageManager {
	m := &ManageManager{
		mfaService:              service.NewMfaService(db),
		identityProviderService: service.NewAppIdentityProviderService(r.Spaces()),
		r:                       r,
	}

	return m
}

func (m *ManageManager) CreateApplication(ctx echo.Context, form *models.ApplicationForm) (*models.Application, *models.GeneralError) {
	space, err := m.r.Spaces().FindByID(context.TODO(), entity.SpaceID(form.SpaceId.Hex()))
	if err != nil {
		return nil, &models.GeneralError{Message: "Unable to get space", Err: errors.Wrap(err, "Unable to get space")}
	}

	defaultRedirectUri := fmt.Sprintf("%s://%s/oauth2/callback", ctx.Scheme(), ctx.Request().Host)
	form.Application.AuthRedirectUrls = append(form.Application.AuthRedirectUrls, defaultRedirectUri)

	appID := bson.NewObjectId()
	app := &models.Application{
		ID:                     appID,
		SpaceId:                bson.ObjectIdHex(string(space.ID)),
		Name:                   form.Application.Name,
		Description:            form.Application.Description,
		IsActive:               form.Application.IsActive,
		CreatedAt:              time.Now(),
		UpdatedAt:              time.Now(),
		AuthSecret:             helper.GetRandString(64),
		AuthRedirectUrls:       form.Application.AuthRedirectUrls,
		PostLogoutRedirectUrls: form.Application.PostLogoutRedirectUrls,
		HasSharedUsers:         form.Application.HasSharedUsers,
		UniqueUsernames:        form.Application.UniqueUsernames,
		RequiresCaptcha:        form.Application.RequiresCaptcha,
		OneTimeTokenSettings: &models.OneTimeTokenSettings{
			Length: 64,
			TTL:    3600,
		},
		WebHooks: form.Application.Webhooks,
	}

	if err := m.r.ApplicationService().Create(app); err != nil {
		return nil, &models.GeneralError{Message: "Unable to create application", Err: errors.Wrap(err, "Unable to create application")}
	}

	_, err = m.r.HydraAdminApi().CreateOAuth2Client(&admin.CreateOAuth2ClientParams{
		Context: ctx.Request().Context(),
		Body: &hydra_models.OAuth2Client{
			ClientID:               app.ID.Hex(),
			ClientName:             app.Name,
			ClientSecret:           app.AuthSecret,
			GrantTypes:             []string{"authorization_code", "refresh_token", "implicit"},
			ResponseTypes:          []string{"code", "id_token", "token"},
			RedirectUris:           app.AuthRedirectUrls,
			PostLogoutRedirectUris: app.PostLogoutRedirectUrls,
			Scope:                  "openid offline",
		},
	})
	if err != nil {
		return nil, &models.GeneralError{Message: "Unable to create hydra client", Err: errors.Wrap(err, "Unable to create hydra client")}
	}

	return app, nil
}

func (m *ManageManager) UpdateApplication(ctx echo.Context, id string, form *models.ApplicationForm) (*models.Application, *models.GeneralError) {
	a, err := m.r.ApplicationService().Get(bson.ObjectIdHex(id))
	if err != nil {
		return nil, &models.GeneralError{Message: "Unable to get application", Err: errors.Wrap(err, "Unable to get application")}
	}

	defaultRedirectUri := fmt.Sprintf("%s://%s/oauth2/callback", ctx.Scheme(), ctx.Request().Host)
	hasDefaultRedirectUri := false
	for _, url := range form.Application.AuthRedirectUrls {
		if url == defaultRedirectUri {
			hasDefaultRedirectUri = true
		}

	}
	if hasDefaultRedirectUri == false {
		form.Application.AuthRedirectUrls = append(form.Application.AuthRedirectUrls, defaultRedirectUri)
	}

	a.SpaceId = form.SpaceId
	a.Name = form.Application.Name
	a.Description = form.Application.Description
	a.IsActive = form.Application.IsActive
	a.UpdatedAt = time.Now()
	a.AuthRedirectUrls = form.Application.AuthRedirectUrls
	a.PostLogoutRedirectUrls = form.Application.PostLogoutRedirectUrls
	a.HasSharedUsers = form.Application.HasSharedUsers
	a.UniqueUsernames = form.Application.UniqueUsernames
	a.RequiresCaptcha = form.Application.RequiresCaptcha
	a.WebHooks = form.Application.Webhooks

	if err := m.r.ApplicationService().Update(a); err != nil {
		return nil, &models.GeneralError{Message: "Unable to update application", Err: errors.Wrap(err, "Unable to update application")}
	}

	client, err := m.r.HydraAdminApi().GetOAuth2Client(&admin.GetOAuth2ClientParams{ID: id, Context: ctx.Request().Context()})
	if err != nil {
		return nil, &models.GeneralError{Message: "Unable to get hydra client", Err: errors.Wrap(err, "Unable to get hydra client")}
	}

	client.Payload.RedirectUris = form.Application.AuthRedirectUrls
	client.Payload.PostLogoutRedirectUris = form.Application.PostLogoutRedirectUrls

	_, err = m.r.HydraAdminApi().UpdateOAuth2Client(&admin.UpdateOAuth2ClientParams{ID: id, Body: client.Payload, Context: ctx.Request().Context()})
	if err != nil {
		return nil, &models.GeneralError{Message: "Unable to update hydra client", Err: errors.Wrap(err, "Unable to update hydra client")}
	}

	return a, nil
}

func (m *ManageManager) GetApplication(ctx echo.Context, id string) (*models.Application, *models.GeneralError) {
	s, err := m.r.ApplicationService().Get(bson.ObjectIdHex(id))
	if err != nil {
		return nil, &models.GeneralError{Message: "Unable to get application", Err: errors.Wrap(err, "Unable to get application")}
	}

	return s, nil
}

func (m *ManageManager) AddMFA(ctx echo.Context, f *models.MfaApplicationForm) (*models.MfaProvider, *models.GeneralError) {
	p := &models.MfaProvider{
		ID:      bson.NewObjectId(),
		AppID:   f.AppId,
		Name:    f.MfaProvider.Name,
		Channel: f.MfaProvider.Channel,
		Type:    f.MfaProvider.Type,
	}

	if err := m.mfaService.Add(p); err != nil {
		return nil, &models.GeneralError{Message: "Unable to add MFA provider", Err: errors.Wrap(err, "Unable to add MFA provider")}
	}

	return p, nil
}

func (m *ManageManager) GetIdentityProviderTemplates() []*models.AppIdentityProvider {
	return m.identityProviderService.GetAllTemplates()
}

func (m *ManageManager) SetOneTimeTokenSettings(ctx echo.Context, appID string, form *models.OneTimeTokenSettings) *models.GeneralError {
	app, err := m.r.ApplicationService().Get(bson.ObjectIdHex(appID))
	if err != nil {
		return &models.GeneralError{Message: "Unable to get application", Err: errors.Wrap(err, "Unable to get application")}
	}

	app.OneTimeTokenSettings = form
	if err := m.r.ApplicationService().Update(app); err != nil {
		return &models.GeneralError{Message: "Unable to save application OneTimeToken settings", Err: errors.Wrap(err, "Unable to save application OneTimeToken settings")}
	}

	return nil
}
