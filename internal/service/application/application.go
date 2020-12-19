package application

import (
	"context"
	"errors"

	"github.com/ProtocolONE/auth1.protocol.one/internal/domain/entity"
)

type Service struct {
	ServiceParams
}

var ErrApplicationNotFound = errors.New("application not found")

func (s Service) GetByID(ctx context.Context, id string) (*entity.Application, error) {
	app, err := s.ApplicationRepo.FindByID(ctx, entity.AppID(id))
	if err != nil {
		return nil, err
	}
	if app == nil {
		return nil, ErrApplicationNotFound
	}
	return app, nil
}
