package manager

import (
	"fmt"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/helper"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/models"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/service"
	"github.com/globalsign/mgo"
	"github.com/globalsign/mgo/bson"
	"github.com/labstack/echo/v4"
	"github.com/ory/hydra/sdk/go/hydra/swagger"
	"github.com/pkg/errors"
	"net/http"
	"time"
)

type ManageManager struct {
	spaceService            *service.SpaceService
	mfaService              *service.MfaService
	identityProviderService *service.AppIdentityProviderService
	r                       service.InternalRegistry
}

func NewManageManager(db *mgo.Session, r service.InternalRegistry) *ManageManager {
	m := &ManageManager{
		spaceService:            service.NewSpaceService(db),
		mfaService:              service.NewMfaService(db),
		identityProviderService: service.NewAppIdentityProviderService(),
		r:                       r,
	}

	return m
}

func (m *ManageManager) CreateSpace(ctx echo.Context, form *models.SpaceForm) (*models.Space, *models.GeneralError) {
	s := &models.Space{
		Id:          bson.NewObjectId(),
		Name:        form.Name,
		Description: form.Description,
		IsActive:    form.IsActive,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	if err := m.spaceService.CreateSpace(s); err != nil {
		return nil, &models.GeneralError{Message: "Unable to create space", Err: errors.Wrap(err, "Unable to create space")}
	}

	return s, nil
}

func (m *ManageManager) UpdateSpace(ctx echo.Context, id string, form *models.SpaceForm) (*models.Space, *models.GeneralError) {
	s, err := m.spaceService.GetSpace(bson.ObjectIdHex(id))
	if err != nil {
		return nil, &models.GeneralError{Message: "Unable to get space", Err: errors.Wrap(err, "Unable to get space")}
	}

	s.Name = form.Name
	s.Description = form.Description
	s.IsActive = form.IsActive

	if err := m.spaceService.UpdateSpace(s); err != nil {
		return nil, &models.GeneralError{Message: "Unable to update space", Err: errors.Wrap(err, "Unable to update space")}
	}

	return s, nil
}

func (m *ManageManager) GetSpace(ctx echo.Context, id string) (*models.Space, *models.GeneralError) {
	s, err := m.spaceService.GetSpace(bson.ObjectIdHex(id))
	if err != nil {
		return nil, &models.GeneralError{Message: "Unable to get space", Err: errors.Wrap(err, "Unable to get space")}
	}

	return s, nil
}

func (m *ManageManager) CreateApplication(ctx echo.Context, form *models.ApplicationForm) (*models.Application, *models.GeneralError) {
	s, err := m.spaceService.GetSpace(form.SpaceId)
	if err != nil {
		return nil, &models.GeneralError{Message: "Unable to get space", Err: errors.Wrap(err, "Unable to get space")}
	}

	defaultRedirectUri := fmt.Sprintf("%s://%s/oauth2/callback", ctx.Scheme(), ctx.Request().Host)
	form.Application.AuthRedirectUrls = append(form.Application.AuthRedirectUrls, defaultRedirectUri)

	appID := bson.NewObjectId()
	app := &models.Application{
		ID:               appID,
		SpaceId:          s.Id,
		Name:             form.Application.Name,
		Description:      form.Application.Description,
		IsActive:         form.Application.IsActive,
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
		AuthSecret:       helper.GetRandString(64),
		AuthRedirectUrls: form.Application.AuthRedirectUrls,
		HasSharedUsers:   form.Application.HasSharedUsers,
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
		IdentityProviders: []*models.AppIdentityProvider{{
			ID:            bson.NewObjectId(),
			ApplicationID: appID,
			Type:          models.AppIdentityProviderTypePassword,
			Name:          models.AppIdentityProviderNameDefault,
			DisplayName:   models.AppIdentityProviderDisplayNameDefault,
		}},
	}

	if err := m.r.ApplicationService().Create(app); err != nil {
		return nil, &models.GeneralError{Message: "Unable to create application", Err: errors.Wrap(err, "Unable to create application")}
	}

	_, response, err := m.r.HydraSDK().AdminApi.CreateOAuth2Client(swagger.OAuth2Client{
		ClientId:      app.ID.Hex(),
		ClientName:    app.Name,
		ClientSecret:  app.AuthSecret,
		GrantTypes:    []string{"authorization_code", "refresh_token", "implicit"},
		ResponseTypes: []string{"code", "id_token", "token"},
		RedirectUris:  app.AuthRedirectUrls,
		Scope:         "openid offline",
	})
	if err != nil || response.StatusCode != http.StatusCreated {
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
	a.HasSharedUsers = form.Application.HasSharedUsers

	if err := m.r.ApplicationService().Update(a); err != nil {
		return nil, &models.GeneralError{Message: "Unable to update application", Err: errors.Wrap(err, "Unable to update application")}
	}

	client, _, err := m.r.HydraSDK().AdminApi.GetOAuth2Client(id)
	if err != nil {
		return nil, &models.GeneralError{Message: "Unable to get hydra client", Err: errors.Wrap(err, "Unable to get hydra client")}
	}

	client.RedirectUris = form.Application.AuthRedirectUrls

	_, _, err = m.r.HydraSDK().AdminApi.UpdateOAuth2Client(id, *client)
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

func (m *ManageManager) AddAppIdentityProvider(ctx echo.Context, form *models.AppIdentityProvider) *models.GeneralError {
	app, err := m.r.ApplicationService().Get(form.ApplicationID)
	if err != nil {
		return &models.GeneralError{Message: "Unable to get application", Err: errors.Wrap(err, "Unable to get application")}
	}

	form.ID = bson.NewObjectId()
	if form.Type == models.AppIdentityProviderTypeSocial {
		if err := m.identityProviderService.NormalizeSocialConnection(form); err != nil {
			return &models.GeneralError{Message: "Unable to normalize identity provider", Err: errors.Wrap(err, "Unable to normalize identity provider")}
		}
	}

	if ip := m.identityProviderService.FindByTypeAndName(app, form.Type, form.Name); ip != nil {
		return &models.GeneralError{Message: "Identity provider already exists", Err: errors.New("Identity provider already exists")}
	}

	if err := m.r.ApplicationService().AddIdentityProvider(app, form); err != nil {
		return &models.GeneralError{Message: "Unable to create identity provider", Err: errors.Wrap(err, "Unable to create identity provider")}
	}

	return nil
}

func (m *ManageManager) UpdateAppIdentityProvider(ctx echo.Context, id string, form *models.AppIdentityProvider) *models.GeneralError {
	app, err := m.r.ApplicationService().Get(form.ApplicationID)
	if err != nil {
		return &models.GeneralError{Message: "Unable to get application", Err: errors.Wrap(err, "Unable to get application")}
	}

	ip := m.identityProviderService.Get(app, bson.ObjectIdHex(id))
	if ip == nil {
		return &models.GeneralError{Message: "Unable to get identity provider", Err: errors.New("Unable to get identity provider")}
	}
	if ip.ApplicationID != form.ApplicationID {
		return &models.GeneralError{Message: "Application not owned this identity provider", Err: errors.New("Application not owned this identity provider")}
	}

	form.ID = ip.ID
	if form.Type == models.AppIdentityProviderTypeSocial {
		if err := m.identityProviderService.NormalizeSocialConnection(form); err != nil {
			return &models.GeneralError{Message: "Unable to normalize identity provider", Err: errors.Wrap(err, "Unable to normalize identity provider")}
		}
	}

	if err := m.r.ApplicationService().UpdateIdentityProvider(app, form); err != nil {
		return &models.GeneralError{Message: "Unable to update identity provider", Err: errors.Wrap(err, "Unable to update identity provider")}
	}

	return nil
}

func (m *ManageManager) GetIdentityProvider(ctx echo.Context, appId string, id string) (*models.AppIdentityProvider, *models.GeneralError) {
	app, err := m.r.ApplicationService().Get(bson.ObjectIdHex(appId))
	if err != nil {
		return nil, &models.GeneralError{Message: "Unable to get application", Err: errors.Wrap(err, "Unable to get application")}
	}

	ipc := m.identityProviderService.Get(app, bson.ObjectIdHex(id))
	if ipc == nil {
		return nil, &models.GeneralError{Message: "Unable to get identity provider", Err: errors.New("Unable to get identity provider")}
	}
	if ipc.ApplicationID.Hex() != appId {
		return nil, &models.GeneralError{Message: "Wrong application id for the identity provider", Err: errors.New("Wrong application id for the identity provider")}
	}

	return ipc, nil
}

func (m *ManageManager) GetIdentityProviders(ctx echo.Context, appId string) ([]*models.AppIdentityProvider, *models.GeneralError) {
	app, err := m.r.ApplicationService().Get(bson.ObjectIdHex(appId))
	if err != nil {
		return nil, &models.GeneralError{Message: "Unable to get application", Err: errors.Wrap(err, "Unable to get application")}
	}

	ipc := m.identityProviderService.FindByType(app, models.AppIdentityProviderTypeSocial)
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
