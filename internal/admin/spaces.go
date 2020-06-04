package admin

import (
	"net/http"
	"strconv"
	"time"

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
	ID               entity.SpaceID       `json:"id"`
	Name             string               `json:"name"`
	Description      string               `json:"description"`
	UniqueUsernames  bool                 `json:"unique_usernames"`
	RequiresCaptcha  bool                 `json:"requires_captcha"`
	PasswordSettings passwordSettingsView `json:"password_settings"`
	CreatedAt        time.Time            `json:"created_at"`
	UpdatedAt        time.Time            `json:"updated_at"`
}

type passwordSettingsView struct {
	BcryptCost     int  `json:"bcrypt_cost"`
	Min            int  `json:"min"`
	Max            int  `json:"max"`
	RequireNumber  bool `json:"require_number"`
	RequireUpper   bool `json:"require_upper"`
	RequireSpecial bool `json:"require_special"`
	RequireLetter  bool `json:"require_letter"`
	TokenLength    int  `json:"token_length"`
	TokenTTL       int  `json:"token_ttl"`
}

type spaceShortView struct {
	ID          entity.SpaceID `json:"id"`
	Name        string         `json:"name"`
	Description string         `json:"description"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
}

func (h *SpaceHandler) List(ctx echo.Context) error {
	sx, err := h.spaces.Find(ctx.Request().Context())
	if err != nil {
		return err
	}

	result := make([]spaceShortView, 0, len(sx))
	for i := range sx {
		result = append(result, h.shortView(sx[i]))
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

func (h *SpaceHandler) Create(ctx echo.Context) error {
	space := entity.NewSpace()
	var request = h.view(space)
	if err := ctx.Bind(&request); err != nil {
		return err
	}

	space.Name = request.Name
	space.Description = request.Description

	if err := h.spaces.Create(ctx.Request().Context(), space); err != nil {
		return err
	}

	return ctx.JSON(http.StatusOK, h.view(space))
}

func (h *SpaceHandler) Update(ctx echo.Context) error {
	id := entity.SpaceID(ctx.Param("id"))

	var request spaceView
	if err := ctx.Bind(&request); err != nil {
		return err
	}

	space, err := h.spaces.FindByID(ctx.Request().Context(), id)
	if err != nil {
		return err
	}

	space.Name = request.Name
	space.Description = request.Description
	space.PasswordSettings = entity.PasswordSettings(request.PasswordSettings)
	space.UniqueUsernames = request.UniqueUsernames
	space.RequiresCaptcha = request.RequiresCaptcha

	if err := h.spaces.Update(ctx.Request().Context(), space); err != nil {
		return err
	}

	return ctx.JSON(http.StatusOK, h.view(space))
}

func (h *SpaceHandler) view(s *entity.Space) spaceView {
	return spaceView{
		ID:               s.ID,
		Name:             s.Name,
		Description:      s.Description,
		UniqueUsernames:  s.UniqueUsernames,
		RequiresCaptcha:  s.RequiresCaptcha,
		PasswordSettings: passwordSettingsView(s.PasswordSettings),
		CreatedAt:        s.CreatedAt,
		UpdatedAt:        s.UpdatedAt,
	}
}

func (h *SpaceHandler) shortView(s *entity.Space) spaceShortView {
	return spaceShortView{
		ID:          s.ID,
		Name:        s.Name,
		Description: s.Description,
		CreatedAt:   s.CreatedAt,
		UpdatedAt:   s.UpdatedAt,
	}
}
