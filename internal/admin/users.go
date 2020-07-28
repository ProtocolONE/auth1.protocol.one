package admin

import (
	"net/http"
	"strconv"

	"github.com/ProtocolONE/auth1.protocol.one/internal/domain/entity"
	"github.com/ProtocolONE/auth1.protocol.one/internal/domain/repository"
	"github.com/labstack/echo/v4"
)

type UsersHandler struct {
	users repository.UserRepository
}

func NewUsersHandler(s repository.UserRepository) *UsersHandler {
	return &UsersHandler{s}
}

type userView struct {
	ID       entity.UserID `json:"id"`
	Username string        `json:"name"`
	Email    string        `json:"email"`
}

func (h *UsersHandler) List(ctx echo.Context) error {
	sx, err := h.users.Find(ctx.Request().Context())
	if err != nil {
		return err
	}

	result := make([]userView, 0, len(sx))
	for i := range sx {
		result = append(result, h.view(sx[i]))
	}

	ctx.Response().Header().Add("X-Total-Count", strconv.Itoa(len(sx)))

	return ctx.JSON(http.StatusOK, result)
}

func (h *UsersHandler) Get(ctx echo.Context) error {
	id := entity.UserID(ctx.Param("id"))

	sx, err := h.users.FindByID(ctx.Request().Context(), id)
	if err != nil {
		return err
	}

	return ctx.JSON(http.StatusOK, h.view(sx))
}

func (h *UsersHandler) view(s *entity.User) userView {
	return userView{
		ID:       s.ID,
		Username: s.Username,
		Email:    s.Email,
	}
}