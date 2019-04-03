package manager

import (
	"errors"
	"fmt"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/helper"
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
	spaceService *models.SpaceService
	appService   *models.ApplicationService
	mfaService   *models.MfaService
	hydraSDK     *hydra.CodeGenSDK
}

func NewManageManager(db *mgo.Session, h *hydra.CodeGenSDK) *ManageManager {
	m := &ManageManager{
		spaceService: models.NewSpaceService(db),
		appService:   models.NewApplicationService(db),
		mfaService:   models.NewMfaService(db),
		hydraSDK:     h,
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
		zap.L().Error(
			"Unable to create space",
			zap.Object("space", s),
			zap.Error(err),
			zap.String(echo.HeaderXRequestID, helper.GetRequestIdFromHeader(ctx)),
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
		zap.L().Error(
			"Unable to update space",
			zap.Object("space", s),
			zap.Error(err),
			zap.String(echo.HeaderXRequestID, helper.GetRequestIdFromHeader(ctx)),
		)
		return nil, err
	}

	return s, nil
}

func (m *ManageManager) GetSpace(ctx echo.Context, id string) (*models.Space, error) {
	s, err := m.spaceService.GetSpace(bson.ObjectIdHex(id))
	if err != nil {
		zap.L().Error(
			"Unable to get space",
			zap.String("spaceId", id),
			zap.Error(err),
			zap.String(echo.HeaderXRequestID, helper.GetRequestIdFromHeader(ctx)),
		)
		return nil, err
	}

	return s, nil
}

func (m *ManageManager) CreateApplication(ctx echo.Context, form *models.ApplicationForm) (*models.Application, error) {
	s, err := m.spaceService.GetSpace(form.SpaceId)
	if err != nil {
		zap.L().Error(
			"Unable to get space",
			zap.String("spaceId", form.SpaceId.String()),
			zap.Error(err),
			zap.String(echo.HeaderXRequestID, helper.GetRequestIdFromHeader(ctx)),
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
	}

	if err := m.appService.Create(app); err != nil {
		zap.L().Error(
			"Unable to create application",
			zap.Object("Application", app),
			zap.Error(err),
			zap.String(echo.HeaderXRequestID, helper.GetRequestIdFromHeader(ctx)),
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
		zap.L().Error(
			"Unable to create hydra client",
			zap.Object("Application", app),
			zap.Error(err),
			zap.String(echo.HeaderXRequestID, helper.GetRequestIdFromHeader(ctx)),
		)
		return nil, err
	}

	return app, nil
}

func (m *ManageManager) UpdateApplication(ctx echo.Context, id string, form *models.ApplicationForm) (*models.Application, error) {
	a, err := m.appService.Get(bson.ObjectIdHex(id))
	if err != nil {
		zap.L().Error(
			"Unable to get app",
			zap.String("AppId", id),
			zap.Error(err),
			zap.String(echo.HeaderXRequestID, helper.GetRequestIdFromHeader(ctx)),
		)
		return nil, errors.New("application not exists")
	}

	if _, err := m.spaceService.GetSpace(form.SpaceId); err != nil {
		zap.L().Error(
			"Unable to get space",
			zap.Object("ApplicationForm", form),
			zap.Error(err),
			zap.String(echo.HeaderXRequestID, helper.GetRequestIdFromHeader(ctx)),
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

	if err := m.appService.Update(a); err != nil {
		zap.L().Error(
			"Unable to update application",
			zap.Object("Application", a),
			zap.Error(err),
			zap.String(echo.HeaderXRequestID, helper.GetRequestIdFromHeader(ctx)),
		)
		return nil, err
	}

	client, response, err := m.hydraSDK.AdminApi.GetOAuth2Client(id)
	zap.L().Error(
		"GET HYDRA CLIENT",
		zap.Any("Client", client),
		zap.Any("Response", response),
		zap.Error(err),
		zap.String(echo.HeaderXRequestID, helper.GetRequestIdFromHeader(ctx)),
	)
	if err != nil {
		zap.L().Error(
			"Unable to get hydra client",
			zap.Object("Application", a),
			zap.Error(err),
			zap.String(echo.HeaderXRequestID, helper.GetRequestIdFromHeader(ctx)),
		)
		return nil, err
	}

	client.RedirectUris = form.Application.AuthRedirectUrls

	_, _, err = m.hydraSDK.AdminApi.UpdateOAuth2Client(id, *client)
	if err != nil {
		zap.L().Error(
			"Unable to update hydra client",
			zap.Object("Application", a),
			zap.Error(err),
			zap.String(echo.HeaderXRequestID, helper.GetRequestIdFromHeader(ctx)),
		)
		return nil, err
	}

	return a, nil
}

func (m *ManageManager) GetApplication(ctx echo.Context, id string) (*models.Application, error) {
	s, err := m.appService.Get(bson.ObjectIdHex(id))
	if err != nil {
		zap.L().Error(
			"Unable to get app",
			zap.String("AppId", id),
			zap.Error(err),
			zap.String(echo.HeaderXRequestID, helper.GetRequestIdFromHeader(ctx)),
		)
		return nil, err
	}

	return s, nil
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
		zap.L().Error(
			"Unable to add MFA provider to application",
			zap.Object("MfaProvider", p),
			zap.Error(err),
			zap.String(echo.HeaderXRequestID, helper.GetRequestIdFromHeader(ctx)),
		)
		return nil, &models.CommonError{Code: `provider_id`, Message: models.ErrorProviderIdIncorrect}
	}

	return p, nil
}
