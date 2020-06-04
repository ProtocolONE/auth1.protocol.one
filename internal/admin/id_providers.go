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
	ID                  entity.IdentityProviderID `json:"id"`
	SpaceID             entity.SpaceID            `json:"space_id"`
	Name                string                    `json:"name"`
	Type                entity.IDProviderType     `json:"type"`
	DisplayName         string                    `json:"display_name"`
	ClientID            string                    `json:"client_id"`
	ClientSecret        string                    `json:"client_secret"`
	ClientScopes        []string                  `json:"client_scopes"`
	EndpointAuthURL     string                    `json:"endpoint_auth_url"`
	EndpointTokenURL    string                    `json:"endpoint_token_url"`
	EndpointUserInfoURL string                    `json:"endpoint_user_info_url"`
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

	space, err := h.spaces.FindForProvider(ctx.Request().Context(), id)
	if err != nil {
		return err
	}

	p, ok := space.IDProvider(id)
	if !ok {
		return ctx.NoContent(http.StatusNotFound)
	}

	return ctx.JSON(http.StatusOK, h.view(space, p))
}

func (h *ProvidersHandler) Create(ctx echo.Context) error {
	var request providerView
	if err := ctx.Bind(&request); err != nil {
		return err
	}

	space, err := h.spaces.FindByID(ctx.Request().Context(), request.SpaceID)
	if err != nil {
		return err
	}

	var p = entity.IdentityProvider{
		Name:                request.Name,
		Type:                request.Type,
		DisplayName:         request.DisplayName,
		ClientID:            request.ClientID,
		ClientSecret:        request.ClientSecret,
		ClientScopes:        request.ClientScopes,
		EndpointAuthURL:     request.EndpointAuthURL,
		EndpointTokenURL:    request.EndpointTokenURL,
		EndpointUserInfoURL: request.EndpointUserInfoURL,
	}
	if err := space.AddIDProvider(p); err != nil {
		return err
	}

	if err := h.spaces.Update(ctx.Request().Context(), space); err != nil {
		return err
	}

	nv, _ := space.IDProviderName(p.Name)

	return ctx.JSON(http.StatusOK, h.view(space, nv))
}

func (h *ProvidersHandler) Update(ctx echo.Context) error {
	id := entity.IdentityProviderID(ctx.Param("id"))

	var request providerView
	if err := ctx.Bind(&request); err != nil {
		return err
	}

	space, err := h.spaces.FindForProvider(ctx.Request().Context(), id)
	if err != nil {
		return err
	}

	p, ok := space.IDProvider(id)
	if !ok {
		return ctx.NoContent(http.StatusNotFound)
	}

	p.Name = request.Name
	p.DisplayName = request.DisplayName
	p.ClientID = request.ClientID
	p.ClientSecret = request.ClientSecret
	p.ClientScopes = request.ClientScopes
	p.EndpointAuthURL = request.EndpointAuthURL
	p.EndpointTokenURL = request.EndpointTokenURL
	p.EndpointUserInfoURL = request.EndpointUserInfoURL

	if err := space.UpdateIDProvider(p); err != nil {
		return err
	}

	if err := h.spaces.Update(ctx.Request().Context(), space); err != nil {
		return err
	}

	nv, _ := space.IDProvider(id)

	return ctx.JSON(http.StatusOK, h.view(space, nv))
}

func (h *ProvidersHandler) Delete(ctx echo.Context) error {
	id := entity.IdentityProviderID(ctx.Param("id"))

	space, err := h.spaces.FindForProvider(ctx.Request().Context(), id)
	if err != nil {
		return err
	}

	if err := space.RemoveIDProvider(id); err != nil {
		return err
	}

	if err := h.spaces.Update(ctx.Request().Context(), space); err != nil {
		return err
	}

	return ctx.NoContent(http.StatusNoContent)
}

func (h *ProvidersHandler) view(s *entity.Space, p entity.IdentityProvider) providerView {
	return providerView{
		ID:                  p.ID,
		SpaceID:             s.ID,
		Name:                p.Name,
		Type:                p.Type,
		DisplayName:         p.DisplayName,
		ClientID:            p.ClientID,
		ClientSecret:        p.ClientSecret,
		ClientScopes:        p.ClientScopes,
		EndpointAuthURL:     p.EndpointAuthURL,
		EndpointTokenURL:    p.EndpointTokenURL,
		EndpointUserInfoURL: p.EndpointUserInfoURL,
	}
}
