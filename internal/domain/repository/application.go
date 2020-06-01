package repository

import (
	"context"

	"github.com/ProtocolONE/auth1.protocol.one/internal/domain/entity"
)

//go:generate mockgen -destination=../mocks/application_repository.go -package=mocks github.com/ProtocolONE/auth1.protocol.one/internal/domain/repository ApplicationRepository
type ApplicationRepository interface {
	FindByID(ctx context.Context, id string) (*entity.Application, error)
}
