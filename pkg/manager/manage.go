package manager

import (
	"auth-one-api/pkg/database"
	"auth-one-api/pkg/models"
	"errors"
	"go.uber.org/zap"
	"gopkg.in/mgo.v2/bson"
	"time"
)

type ManageManager struct {
	logger       *zap.Logger
	spaceService *models.SpaceService
	appService   *models.ApplicationService
	mfaService   *models.MfaService
}

func NewManageManager(logger *zap.Logger, db *database.Handler) *ManageManager {
	m := &ManageManager{
		logger:       logger,
		spaceService: models.NewSpaceService(db),
		appService:   models.NewApplicationService(db),
		mfaService:   models.NewMfaService(db),
	}

	return m
}

func (m *ManageManager) CreateSpace(form *models.SpaceForm) (*models.Space, error) {
	s := &models.Space{
		Id:          bson.NewObjectId(),
		Name:        form.Name,
		Description: form.Description,
		IsActive:    form.IsActive,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	if err := m.spaceService.CreateSpace(s); err != nil {
		m.logger.Error(
			"Unable to create space",
			zap.Object("space", s),
			zap.Error(err),
		)

		return nil, err
	}

	return s, nil
}

func (m *ManageManager) UpdateSpace(id string, form *models.SpaceForm) (*models.Space, error) {
	s, err := m.spaceService.GetSpace(bson.ObjectIdHex(id))
	if err != nil {
		return nil, err
	}

	s.Name = form.Name
	s.Description = form.Description
	s.IsActive = form.IsActive

	if err := m.spaceService.UpdateSpace(s); err != nil {
		m.logger.Error(
			"Unable to update space",
			zap.Object("space", s),
			zap.Error(err),
		)

		return nil, err
	}

	return s, nil
}

func (m *ManageManager) GetSpace(id string) (*models.Space, error) {
	s, err := m.spaceService.GetSpace(bson.ObjectIdHex(id))
	if err != nil {
		m.logger.Error(
			"Unable to get space",
			zap.String("spaceId", id),
			zap.Error(err),
		)

		return nil, err
	}

	return s, nil
}

func (m *ManageManager) CreateApplication(form *models.ApplicationForm) (*models.Application, error) {
	s, err := m.spaceService.GetSpace(form.SpaceId)
	if err != nil {
		m.logger.Error(
			"Unable to get space",
			zap.String("spaceId", form.SpaceId.String()),
			zap.Error(err),
		)

		return nil, err
	}

	app := &models.Application{
		ID:          bson.NewObjectId(),
		SpaceId:     s.Id,
		Name:        form.Application.Name,
		Description: form.Application.Description,
		IsActive:    form.Application.IsActive,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	if err := m.appService.Create(app); err != nil {
		m.logger.Error(
			"Unable to create application",
			zap.Object("Application", app),
			zap.Error(err),
		)

		return nil, err
	}

	return app, nil
}

func (m *ManageManager) UpdateApplication(id string, form *models.ApplicationForm) (*models.Application, error) {
	a, err := m.appService.Get(bson.ObjectIdHex(id))
	if err != nil {
		m.logger.Error(
			"Unable to get app",
			zap.String("AppId", id),
			zap.Error(err),
		)

		return nil, errors.New("application not exists")
	}

	if _, err := m.spaceService.GetSpace(form.SpaceId); err != nil {
		m.logger.Error(
			"Unable to get space",
			zap.Object("ApplicationForm", form),
			zap.Error(err),
		)

		return nil, errors.New("space not exists")
	}

	a.SpaceId = form.SpaceId
	a.Name = form.Application.Name
	a.Description = form.Application.Description
	a.IsActive = form.Application.IsActive
	a.UpdatedAt = time.Now()

	if err := m.appService.Update(a); err != nil {
		m.logger.Error(
			"Unable to update application",
			zap.Object("Application", a),
			zap.Error(err),
		)

		return nil, err
	}

	return a, nil
}

func (m *ManageManager) GetApplication(id string) (*models.Application, error) {
	s, err := m.appService.Get(bson.ObjectIdHex(id))
	if err != nil {
		m.logger.Error(
			"Unable to get app",
			zap.String("AppId", id),
			zap.Error(err),
		)

		return nil, err
	}

	return s, nil
}

func (m *ManageManager) AddMFA(f *models.MfaApplicationForm) (*models.MfaProvider, error) {
	p := &models.MfaProvider{
		ID:      bson.NewObjectId(),
		AppID:   f.AppId,
		Name:    f.MfaProvider.Name,
		Channel: f.MfaProvider.Channel,
		Type:    f.MfaProvider.Type,
	}

	if err := m.mfaService.Add(p); err != nil {
		m.logger.Error(
			"Unable to add MFA provider to application",
			zap.Object("MfaProvider", p),
			zap.Error(err),
		)

		return nil, &models.CommonError{Code: `provider_id`, Message: models.ErrorProviderIdIncorrect}
	}

	return p, nil
}
