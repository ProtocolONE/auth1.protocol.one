package manager

import (
	"fmt"
	"time"

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
		identityProviderService: service.NewAppIdentityProviderService(r.SpaceService(), r.Spaces()),
		r:                       r,
	}

	return m
}

func (m *ManageManager) CreateApplication(ctx echo.Context, form *models.ApplicationForm) (*models.Application, *models.GeneralError) {
	s, err := m.r.SpaceService().GetSpace(form.SpaceId)
	if err != nil {
		return nil, &models.GeneralError{Message: "Unable to get space", Err: errors.Wrap(err, "Unable to get space")}
	}

	defaultRedirectUri := fmt.Sprintf("%s://%s/oauth2/callback", ctx.Scheme(), ctx.Request().Host)
	form.Application.AuthRedirectUrls = append(form.Application.AuthRedirectUrls, defaultRedirectUri)

	appID := bson.NewObjectId()
	app := &models.Application{
		ID:                     appID,
		SpaceId:                s.ID,
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
		PasswordSettings: &models.PasswordSettings{
			BcryptCost:     models.PasswordBcryptCostDefault,
			Min:            models.PasswordMinDefault,
			Max:            models.PasswordMaxDefault,
			RequireNumber:  models.PasswordRequireNumberDefault,
			RequireUpper:   models.PasswordRequireUpperDefault,
			RequireSpecial: models.PasswordRequireSpecialDefault,
			TokenLength:    models.PasswordTokenLengthDefault,
			TokenTTL:       models.PasswordTokenTTLDefault,
		},
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

func (m *ManageManager) SetPasswordSettings(ctx echo.Context, appID string, form *models.PasswordSettings) *models.GeneralError {
	app, err := m.r.ApplicationService().Get(bson.ObjectIdHex(appID))
	if err != nil {
		return &models.GeneralError{Message: "Unable to get application", Err: errors.Wrap(err, "Unable to get application")}
	}

	app.PasswordSettings = &models.PasswordSettings{
		BcryptCost:     form.BcryptCost,
		Min:            form.Min,
		Max:            form.Max,
		RequireNumber:  form.RequireNumber,
		RequireUpper:   form.RequireUpper,
		RequireSpecial: form.RequireSpecial,
		TokenLength:    form.TokenLength,
		TokenTTL:       form.TokenTTL,
	}
	if err := m.r.ApplicationService().Update(app); err != nil {
		return &models.GeneralError{Message: "Unable to save application password", Err: errors.Wrap(err, "Unable to save application password")}
	}

	return nil
}

func (m *ManageManager) GetPasswordSettings(id string) (*models.PasswordSettings, *models.GeneralError) {
	app, err := m.r.ApplicationService().Get(bson.ObjectIdHex(id))
	if err != nil {
		return nil, &models.GeneralError{Message: "Unable to get application", Err: errors.Wrap(err, "Unable to get application")}
	}

	return app.PasswordSettings, nil
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

func (m *ManageManager) AddAppIdentityProvider(spaceID string, form *models.AppIdentityProvider) *models.GeneralError {
	space, err := m.r.SpaceService().GetSpace(bson.ObjectIdHex(spaceID))
	if err != nil {
		return &models.GeneralError{Message: "Unable to get application", Err: errors.Wrap(err, "Unable to get application")}
	}

	form.ID = bson.NewObjectId()
	if form.Type == models.AppIdentityProviderTypeSocial {
		if err := m.identityProviderService.NormalizeSocialConnection(form); err != nil {
			return &models.GeneralError{Message: "Unable to normalize identity provider", Err: errors.Wrap(err, "Unable to normalize identity provider")}
		}
	}

	if ip := m.identityProviderService.FindByTypeAndNameSpace(space, form.Type, form.Name); ip != nil {
		return &models.GeneralError{Message: "Identity provider already exists", Err: errors.New("Identity provider already exists")}
	}

	if err := m.r.SpaceService().AddIdentityProvider(space, form); err != nil {
		return &models.GeneralError{Message: "Unable to create identity provider", Err: errors.Wrap(err, "Unable to create identity provider")}
	}

	return nil
}

func (m *ManageManager) UpdateAppIdentityProvider(spaceID string, id string, form *models.AppIdentityProvider) *models.GeneralError {
	space, err := m.r.SpaceService().GetSpace(bson.ObjectIdHex(spaceID))
	if err != nil {
		return &models.GeneralError{Message: "Unable to get application", Err: errors.Wrap(err, "Unable to get application")}
	}

	ip := m.identityProviderService.GetSpace(space, bson.ObjectIdHex(id))
	if ip == nil {
		return &models.GeneralError{Message: "Unable to get identity provider", Err: errors.New("Unable to get identity provider")}
	}

	form.ID = ip.ID
	if form.Type == models.AppIdentityProviderTypeSocial {
		if err := m.identityProviderService.NormalizeSocialConnection(form); err != nil {
			return &models.GeneralError{Message: "Unable to normalize identity provider", Err: errors.Wrap(err, "Unable to normalize identity provider")}
		}
	}

	if err := m.r.SpaceService().UpdateIdentityProvider(space, form); err != nil {
		return &models.GeneralError{Message: "Unable to update identity provider", Err: errors.Wrap(err, "Unable to update identity provider")}
	}

	return nil
}

func (m *ManageManager) GetIdentityProvider(ctx echo.Context, spaceId string, id string) (*models.AppIdentityProvider, *models.GeneralError) {
	space, err := m.r.SpaceService().GetSpace(bson.ObjectIdHex(spaceId))
	if err != nil {
		return nil, &models.GeneralError{Message: "Unable to get application", Err: errors.Wrap(err, "Unable to get application")}
	}

	ipc := m.identityProviderService.GetSpace(space, bson.ObjectIdHex(id))
	if ipc == nil {
		return nil, &models.GeneralError{Message: "Unable to get identity provider", Err: errors.New("Unable to get identity provider")}
	}

	return ipc, nil
}

func (m *ManageManager) GetIdentityProviders(ctx echo.Context, spaceID string) ([]*models.AppIdentityProvider, *models.GeneralError) {
	space, err := m.r.SpaceService().GetSpace(bson.ObjectIdHex(spaceID))
	if err != nil {
		return nil, &models.GeneralError{Message: "Unable to get application", Err: errors.Wrap(err, "Unable to get application")}
	}

	ipc := m.identityProviderService.FindByTypeSpace(space, models.AppIdentityProviderTypeSocial)
	if ipc == nil && len(ipc) > 0 {
		return nil, &models.GeneralError{Message: "Unable to get identity provider", Err: errors.New("Unable to get identity provider")}
	}

	return ipc, nil
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
