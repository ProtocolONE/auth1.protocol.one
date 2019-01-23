package manager

import (
	"auth-one-api/pkg/database"
	"auth-one-api/pkg/models"
	"errors"
	"fmt"
	"github.com/sirupsen/logrus"
	"gopkg.in/mgo.v2/bson"
	"time"
)

type ManageManager Config

func (m *ManageManager) CreateSpace(form *models.SpaceForm) (*models.Space, error) {
	s := &models.Space{
		Id:          bson.NewObjectId(),
		Name:        form.Name,
		Description: form.Description,
		IsActive:    form.IsActive,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	ss := models.NewSpaceService(m.Database)
	if err := ss.CreateSpace(s); err != nil {
		return nil, err
	}

	return s, nil
}

func (m *ManageManager) UpdateSpace(id string, form *models.SpaceForm) (*models.Space, error) {
	ss := models.NewSpaceService(m.Database)
	s, err := ss.GetSpace(bson.ObjectIdHex(id))
	if err != nil {
		return nil, err
	}

	s.Name = form.Name
	s.Description = form.Description
	s.IsActive = form.IsActive

	if err := ss.UpdateSpace(s); err != nil {
		return nil, err
	}

	return s, nil
}

func (m *ManageManager) GetSpace(id string) (*models.Space, error) {
	ss := models.NewSpaceService(m.Database)
	s, err := ss.GetSpace(bson.ObjectIdHex(id))
	if err != nil {
		return nil, err
	}

	return s, nil
}

func (m *ManageManager) CreateApplication(form *models.ApplicationForm) (*models.Application, error) {
	ss := models.NewSpaceService(m.Database)
	s, err := ss.GetSpace(form.SpaceId)
	if err != nil {
		return nil, err
	}

	a := &models.Application{
		ID:          bson.NewObjectId(),
		SpaceId:     s.Id,
		Name:        form.Application.Name,
		Description: form.Application.Description,
		IsActive:    form.Application.IsActive,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	as := models.NewApplicationService(m.Database)
	if err := as.Create(a); err != nil {
		return nil, err
	}

	return a, nil
}

func (m *ManageManager) UpdateApplication(id string, form *models.ApplicationForm) (*models.Application, error) {
	as := models.NewApplicationService(m.Database)
	a, err := as.Get(bson.ObjectIdHex(id))
	if err != nil {
		return nil, errors.New("application not exists")
	}

	ss := models.NewSpaceService(m.Database)
	if _, err := ss.GetSpace(form.SpaceId); err != nil {
		return nil, errors.New("space not exists")
	}

	a.SpaceId = form.SpaceId
	a.Name = form.Application.Name
	a.Description = form.Application.Description
	a.IsActive = form.Application.IsActive
	a.UpdatedAt = time.Now()

	if err := as.Update(a); err != nil {
		return nil, err
	}

	return a, nil
}

func (m *ManageManager) GetApplication(id string) (*models.Application, error) {
	ss := models.NewApplicationService(m.Database)
	s, err := ss.Get(bson.ObjectIdHex(id))

	if err != nil {
		return nil, err
	}

	return s, nil
}

func InitManageManager(logger *logrus.Entry, db *database.Handler) ManageManager {
	m := ManageManager{
		Database: db,
		Logger:   logger,
	}

	return m
}

func (m *ManageManager) AddMFA(f *models.MfaApplicationForm) (*models.MfaProvider, error) {
	ms := models.NewMfaService(m.Database)
	p := &models.MfaProvider{
		ID:      bson.NewObjectId(),
		AppID:   f.AppId,
		Name:    f.MfaProvider.Name,
		Channel: f.MfaProvider.Channel,
		Type:    f.MfaProvider.Type,
	}
	if err := ms.Add(p); err != nil {
		m.Logger.Warning(fmt.Sprintf("Unable to add MFA provider [%s] an application [%s] with error: %s", f.MfaProvider.Name, f.AppId, err.Error()))
		return nil, &models.CommonError{Code: `provider_id`, Message: models.ErrorProviderIdIncorrect}
	}

	return p, nil
}
