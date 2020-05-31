package admin

import (
	"net/http"
	"strconv"

	"github.com/ProtocolONE/auth1.protocol.one/internal/domain/entity"
	"github.com/ProtocolONE/auth1.protocol.one/internal/domain/repository"

	"github.com/labstack/echo/v4"
)

type SpaceHandler struct {
	spaces repository.SpaceRepository
}

func NewSpaceHandler(s repository.SpaceRepository) *SpaceHandler {
	return &SpaceHandler{s}
}

type spaceView struct {
	ID          entity.SpaceID `json:"id"`
	Name        string         `json:"name"`
	Description string         `json:"description"`
}

func (h *SpaceHandler) List(ctx echo.Context) error {
	sx, err := h.spaces.Find(ctx.Request().Context())
	if err != nil {
		return err
	}

	result := make([]spaceView, 0, len(sx))
	for i := range sx {
		result = append(result, h.view(sx[i]))
	}

	ctx.Response().Header().Add("X-Total-Count", strconv.Itoa(len(sx)))

	return ctx.JSON(http.StatusOK, result)
}

func (h *SpaceHandler) Get(ctx echo.Context) error {
	id := entity.SpaceID(ctx.Param("id"))

	sx, err := h.spaces.FindByID(ctx.Request().Context(), id)
	if err != nil {
		return err
	}

	return ctx.JSON(http.StatusOK, h.view(sx))
}

func (h *SpaceHandler) view(s *entity.Space) spaceView {
	return spaceView{
		ID:          s.ID,
		Name:        s.Name,
		Description: s.Description,
	}
}
