package admin

import (
	"net/http"
	"strconv"

	"github.com/ProtocolONE/auth1.protocol.one/internal/domain/entity"
	"github.com/ProtocolONE/auth1.protocol.one/internal/domain/repository"
	"github.com/labstack/echo/v4"
)

type UsersHandler struct {
	users  repository.UserRepository
	spaces repository.SpaceRepository
}

func NewUsersHandler(u repository.UserRepository, s repository.SpaceRepository) *UsersHandler {
	return &UsersHandler{u, s}
}

type userView struct {
	ID       entity.UserID `json:"id"`
	Username string        `json:"name"`
	Email    string        `json:"email"`
	Roles    []string      `json:"roles"`
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

func (h *UsersHandler) Update(ctx echo.Context) error {
	id := entity.UserID(ctx.Param("id"))

	var request userView
	if err := ctx.Bind(&request); err != nil {
		return err
	}

	usr, err := h.users.FindByID(ctx.Request().Context(), id)
	if err != nil {
		return err
	}

	space, err := h.spaces.FindByID(ctx.Request().Context(), usr.SpaceID)
	if err != nil {
		return err
	}

	roles := []string{}
	for i := range space.Roles {
		for k := range request.Roles {
			if space.Roles[i] == request.Roles[k] {
				roles = append(roles, space.Roles[i])
			}
		}
	}

	usr.Roles = roles

	err = h.users.Update(ctx.Request().Context(), usr)
	if err != nil {
		return err
	}

	return ctx.JSON(http.StatusOK, h.view(usr))
}

func (h *UsersHandler) view(s *entity.User) userView {
	return userView{
		ID:       s.ID,
		Username: s.Username,
		Email:    s.Email,
		Roles:    s.Roles,
	}
}
