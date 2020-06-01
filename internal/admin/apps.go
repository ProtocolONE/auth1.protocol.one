package admin

import (
	"net/http"
	"strconv"

	"github.com/ProtocolONE/auth1.protocol.one/internal/domain/entity"
	"github.com/ProtocolONE/auth1.protocol.one/internal/domain/repository"
	"github.com/labstack/echo/v4"
)

type ApplicationsHandler struct {
	apps repository.ApplicationRepository
}

func NewApplicationsHandler(s repository.ApplicationRepository) *ApplicationsHandler {
	return &ApplicationsHandler{s}
}

type appView struct {
	ID          entity.AppID `json:"id"`
	Name        string       `json:"name"`
	Description string       `json:"description"`
}

func (h *ApplicationsHandler) List(ctx echo.Context) error {
	sx, err := h.apps.Find(ctx.Request().Context())
	if err != nil {
		return err
	}

	result := make([]appView, 0, len(sx))
	for i := range sx {
		result = append(result, h.view(sx[i]))
	}

	ctx.Response().Header().Add("X-Total-Count", strconv.Itoa(len(sx)))

	return ctx.JSON(http.StatusOK, result)
}

func (h *ApplicationsHandler) Get(ctx echo.Context) error {
	id := entity.AppID(ctx.Param("id"))

	sx, err := h.apps.FindByID(ctx.Request().Context(), id)
	if err != nil {
		return err
	}

	return ctx.JSON(http.StatusOK, h.view(sx))
}

func (h *ApplicationsHandler) view(s *entity.Application) appView {
	return appView{
		ID:          s.ID,
		Name:        s.Name,
		Description: s.Description,
	}
}
