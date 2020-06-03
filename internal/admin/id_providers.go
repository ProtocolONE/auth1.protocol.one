package admin

import (
	"net/http"
	"strconv"

	"github.com/ProtocolONE/auth1.protocol.one/internal/domain/entity"
	"github.com/ProtocolONE/auth1.protocol.one/internal/domain/repository"

	"github.com/labstack/echo/v4"
)

type ProvidersHandler struct {
	spaces repository.SpaceRepository
}

func NewProvidersHandler(s repository.SpaceRepository) *ProvidersHandler {
	return &ProvidersHandler{s}
}

type providerView struct {
	ID          entity.IdentityProviderID `json:"id"`
	SpaceID     entity.SpaceID            `json:"space_id"`
	Name        string                    `json:"name"`
	Type        entity.IDProviderType     `json:"type"`
	DisplayName string                    `json:"display_name"`
}

func (h *ProvidersHandler) List(ctx echo.Context) error {
	sx, err := h.spaces.Find(ctx.Request().Context())
	if err != nil {
		return err
	}

	result := make([]providerView, 0, len(sx))
	for i := range sx {
		for k := range sx[i].IdentityProviders {
			result = append(result, h.view(sx[i], sx[i].IdentityProviders[k]))
		}
	}

	ctx.Response().Header().Add("X-Total-Count", strconv.Itoa(len(result)))

	return ctx.JSON(http.StatusOK, result)
}

func (h *ProvidersHandler) Get(ctx echo.Context) error {
	id := entity.IdentityProviderID(ctx.Param("id"))

	sx, err := h.spaces.Find(ctx.Request().Context())
	if err != nil {
		return err
	}

	for i := range sx {
		for k := range sx[i].IdentityProviders {
			if sx[i].IdentityProviders[k].ID == id {
				return ctx.JSON(http.StatusOK, h.view(sx[i], sx[i].IdentityProviders[k]))
			}
		}
	}

	return ctx.JSON(http.StatusNotFound, nil)
}

func (h *ProvidersHandler) view(s *entity.Space, p entity.IdentityProvider) providerView {
	return providerView{
		ID:          p.ID,
		SpaceID:     s.ID,
		Name:        p.Name,
		Type:        p.Type,
		DisplayName: p.DisplayName,
	}
}
