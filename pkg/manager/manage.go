package manager

import (
	"errors"
	"fmt"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/models"
	"github.com/globalsign/mgo"
	"github.com/globalsign/mgo/bson"
	"github.com/labstack/echo/v4"
	"github.com/ory/hydra/sdk/go/hydra"
	"github.com/ory/hydra/sdk/go/hydra/swagger"
	"go.uber.org/zap"
	"net/http"
	"time"
)

type ManageManager struct {
	Logger                  *zap.Logger
	spaceService            *models.SpaceService
	appService              *models.ApplicationService
	mfaService              *models.MfaService
	hydraSDK                *hydra.CodeGenSDK
	identityProviderService *models.AppIdentityProviderService
}

func NewManageManager(db *mgo.Session, l *zap.Logger, h *hydra.CodeGenSDK) *ManageManager {
	m := &ManageManager{
		spaceService:            models.NewSpaceService(db),
		appService:              models.NewApplicationService(db),
		mfaService:              models.NewMfaService(db),
		identityProviderService: models.NewAppIdentityProviderService(db),
		hydraSDK:                h,
		Logger:                  l,
	}

	return m
}

func (m *ManageManager) CreateSpace(ctx echo.Context, form *models.SpaceForm) (*models.Space, error) {
	s := &models.Space{
		Id:          bson.NewObjectId(),
		Name:        form.Name,
		Description: form.Description,
		IsActive:    form.IsActive,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	if err := m.spaceService.CreateSpace(s); err != nil {
		m.Logger.Error(
			"Unable to create space",
			zap.Object("space", s),
			zap.Error(err),
		)
		return nil, err
	}

	return s, nil
}

func (m *ManageManager) UpdateSpace(ctx echo.Context, id string, form *models.SpaceForm) (*models.Space, error) {
	s, err := m.spaceService.GetSpace(bson.ObjectIdHex(id))
	if err != nil {
		return nil, err
	}

	s.Name = form.Name
	s.Description = form.Description
	s.IsActive = form.IsActive

	if err := m.spaceService.UpdateSpace(s); err != nil {
		m.Logger.Error(
			"Unable to update space",
			zap.Object("space", s),
			zap.Error(err),
		)
		return nil, err
	}

	return s, nil
}

func (m *ManageManager) GetSpace(ctx echo.Context, id string) (*models.Space, error) {
	s, err := m.spaceService.GetSpace(bson.ObjectIdHex(id))
	if err != nil {
		m.Logger.Error(
			"Unable to get space",
			zap.String("spaceId", id),
			zap.Error(err),
		)
		return nil, err
	}

	return s, nil
}

func (m *ManageManager) CreateApplication(ctx echo.Context, form *models.ApplicationForm) (*models.Application, error) {
	s, err := m.spaceService.GetSpace(form.SpaceId)
	if err != nil {
		m.Logger.Error(
			"Unable to get space",
			zap.String("spaceId", form.SpaceId.String()),
			zap.Error(err),
		)
		return nil, err
	}

	defaultRedirectUri := fmt.Sprintf("%s://%s/oauth2/callback", ctx.Scheme(), ctx.Request().Host)
	form.Application.AuthRedirectUrls = append(form.Application.AuthRedirectUrls, defaultRedirectUri)

	app := &models.Application{
		ID:               bson.NewObjectId(),
		SpaceId:          s.Id,
		Name:             form.Application.Name,
		Description:      form.Application.Description,
		IsActive:         form.Application.IsActive,
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
		AuthSecret:       models.GetRandString(64),
		AuthRedirectUrls: form.Application.AuthRedirectUrls,
		HasSharedUsers:   form.Application.HasSharedUsers,
	}

	if err := m.appService.Create(app); err != nil {
		m.Logger.Error(
			"Unable to create application",
			zap.Object("Application", app),
			zap.Error(err),
		)
		return nil, err
	}

	_, response, err := m.hydraSDK.AdminApi.CreateOAuth2Client(swagger.OAuth2Client{
		ClientId:      app.ID.Hex(),
		ClientName:    app.Name,
		ClientSecret:  app.AuthSecret,
		GrantTypes:    []string{"authorization_code", "refresh_token", "implicit"},
		ResponseTypes: []string{"code", "id_token", "token"},
		RedirectUris:  app.AuthRedirectUrls,
		Scope:         "openid offline",
	})
	if err != nil || response.StatusCode != http.StatusCreated {
		m.Logger.Error(
			"Unable to create hydra client",
			zap.Object("Application", app),
			zap.Error(err),
		)
		return nil, err
	}

	ps := &models.PasswordSettings{
		ApplicationID:  app.ID,
		BcryptCost:     models.PasswordBcryptCostDefault,
		Min:            models.PasswordMinDefault,
		Max:            models.PasswordMaxDefault,
		RequireNumber:  models.PasswordRequireNumberDefault,
		RequireUpper:   models.PasswordRequireUpperDefault,
		RequireSpecial: models.PasswordRequireSpecialDefault,
		TokenLength:    models.PasswordTokenLengthDefault,
		TokenTTL:       models.PasswordTokenTTLDefault,
	}
	if err := m.appService.SetPasswordSettings(app, ps); err != nil {
		m.Logger.Error(
			"Unable to set default password settings",
			zap.Object("Application", app),
			zap.Object("PasswordSettings", ps),
			zap.Error(err),
		)
		return nil, err
	}

	ipc := &models.AppIdentityProvider{
		ID:            bson.NewObjectId(),
		ApplicationID: app.ID,
		Type:          models.AppIdentityProviderTypePassword,
		Name:          models.AppIdentityProviderNameDefault,
		DisplayName:   "Initial connection",
	}
	if err := m.identityProviderService.Create(ipc); err != nil {
		m.Logger.Error(
			"Unable to add default identity provider",
			zap.Object("Application", app),
			zap.Object("AppIdentityProvider", ipc),
			zap.Error(err),
		)
		return nil, err
	}

	return app, nil
}

func (m *ManageManager) UpdateApplication(ctx echo.Context, id string, form *models.ApplicationForm) (*models.Application, error) {
	a, err := m.appService.Get(bson.ObjectIdHex(id))
	if err != nil {
		return nil, errors.New("application not exists")
	}

	if _, err := m.spaceService.GetSpace(form.SpaceId); err != nil {
		m.Logger.Error(
			"Unable to get space",
			zap.Object("ApplicationForm", form),
			zap.Error(err),
		)
		return nil, errors.New("space not exists")
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

	if err := m.appService.Update(a); err != nil {
		m.Logger.Error(
			"Unable to update application",
			zap.Object("Application", a),
			zap.Error(err),
		)
		return nil, err
	}

	client, response, err := m.hydraSDK.AdminApi.GetOAuth2Client(id)
	m.Logger.Error(
		"GET HYDRA CLIENT",
		zap.Any("Client", client),
		zap.Any("Response", response),
		zap.Error(err),
	)
	if err != nil {
		m.Logger.Error(
			"Unable to get hydra client",
			zap.Object("Application", a),
			zap.Error(err),
		)
		return nil, err
	}

	client.RedirectUris = form.Application.AuthRedirectUrls

	_, _, err = m.hydraSDK.AdminApi.UpdateOAuth2Client(id, *client)
	if err != nil {
		m.Logger.Error(
			"Unable to update hydra client",
			zap.Object("Application", a),
			zap.Error(err),
		)
		return nil, err
	}

	return a, nil
}

func (m *ManageManager) GetApplication(ctx echo.Context, id string) (*models.Application, error) {
	s, err := m.appService.Get(bson.ObjectIdHex(id))
	if err != nil {
		return nil, err
	}

	return s, nil
}

func (m *ManageManager) SetPasswordSettings(ctx echo.Context, form *models.PasswordSettings) error {
	app, err := m.appService.Get(form.ApplicationID)
	if err != nil {
		return err
	}

	if err := m.appService.SetPasswordSettings(app, form); err != nil {
		m.Logger.Error(
			"Unable to set password settings",
			zap.Object("Application", app),
			zap.Object("PasswordSettings", form),
			zap.Error(err),
		)
		return err
	}

	return nil
}

func (m *ManageManager) GetPasswordSettings(id string) (*models.PasswordSettings, error) {
	a, err := m.appService.Get(bson.ObjectIdHex(id))
	if err != nil {
		return nil, err
	}
	ps, err := m.appService.GetPasswordSettings(a)
	if err != nil {
		m.Logger.Warn("Unable to load password settings", zap.Error(err))
		return nil, err
	}

	return ps, nil
}

func (m *ManageManager) AddMFA(ctx echo.Context, f *models.MfaApplicationForm) (*models.MfaProvider, error) {
	p := &models.MfaProvider{
		ID:      bson.NewObjectId(),
		AppID:   f.AppId,
		Name:    f.MfaProvider.Name,
		Channel: f.MfaProvider.Channel,
		Type:    f.MfaProvider.Type,
	}

	if err := m.mfaService.Add(p); err != nil {
		m.Logger.Error(
			"Unable to add MFA provider to application",
			zap.Object("MfaProvider", p),
			zap.Error(err),
		)
		return nil, &models.CommonError{Code: `provider_id`, Message: models.ErrorProviderIdIncorrect}
	}

	return p, nil
}

func (m *ManageManager) AddAppIdentityProvider(ctx echo.Context, form *models.AppIdentityProvider) error {
	if _, err := m.appService.Get(form.ApplicationID); err != nil {
		return err
	}

	form.ID = bson.NewObjectId()
	if form.Type == models.AppIdentityProviderTypeSocial {
		if err := m.identityProviderService.NormalizeSocialConnection(form); err != nil {
			m.Logger.Error(
				"Unable to normalize identity provider",
				zap.Object("AppIdentityProvider", form),
				zap.Error(err),
			)
			return err
		}
	}
	if err := m.identityProviderService.Create(form); err != nil {
		m.Logger.Error(
			"Unable to create identity provider",
			zap.Object("AppIdentityProvider", form),
			zap.Error(err),
		)
		return err
	}

	return nil
}

func (m *ManageManager) UpdateAppIdentityProvider(ctx echo.Context, id string, form *models.AppIdentityProvider) error {
	ip, err := m.identityProviderService.Get(bson.ObjectIdHex(id))
	if err != nil {
		m.Logger.Error(
			"Unable to get identity provider",
			zap.Object("AppIdentityProvider", form),
			zap.Error(err),
		)
		return errors.New("identity provider not exists")
	}
	if ip.ApplicationID != form.ApplicationID {
		m.Logger.Error(
			"Application not owned this identity provider",
			zap.Object("AppIdentityProvider", form),
			zap.Error(err),
		)
		return errors.New("application not owned this identity provider")
	}

	form.ID = ip.ID
	if form.Type == models.AppIdentityProviderTypeSocial {
		if err := m.identityProviderService.NormalizeSocialConnection(form); err != nil {
			m.Logger.Error(
				"Unable to normalize identity provider",
				zap.Object("AppIdentityProvider", form),
				zap.Error(err),
			)
			return err
		}
	}

	if err := m.identityProviderService.Update(form); err != nil {
		m.Logger.Error(
			"Unable to update identity provider",
			zap.Object("AppIdentityProvider", form),
			zap.Error(err),
		)
		return err
	}

	return nil
}

func (m *ManageManager) GetIdentityProvider(ctx echo.Context, appId string, id string) (*models.AppIdentityProvider, error) {
	ipc, err := m.identityProviderService.Get(bson.ObjectIdHex(id))
	if err != nil {
		m.Logger.Error(
			"Unable to get application",
			zap.String("ApplicationID", appId),
			zap.Error(err),
		)
		return nil, err
	}
	if ipc.ApplicationID.Hex() != appId {
		m.Logger.Error(
			"Wrong application id for the identity provider",
			zap.String("ApplicationID", appId),
			zap.Object("IdentityProvider", ipc),
		)
		return nil, errors.New("wrong application id for the identity provider")
	}

	return ipc, nil
}

func (m *ManageManager) GetIdentityProviders(ctx echo.Context, appId string) ([]models.AppIdentityProvider, error) {
	app, err := m.appService.Get(bson.ObjectIdHex(appId))
	if err != nil {
		return nil, err
	}

	ipc, err := m.identityProviderService.FindByType(app, models.AppIdentityProviderTypeSocial)
	if err != nil {
		m.Logger.Error(
			"Unable to get application",
			zap.String("ApplicationID", appId),
			zap.Error(err),
		)
		return nil, err
	}

	return ipc, nil
}

func (m *ManageManager) GetIdentityProviderTemplates() []*models.AppIdentityProvider {
	return m.identityProviderService.GetAllTemplates()
}
