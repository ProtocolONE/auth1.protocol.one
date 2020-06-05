package service

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"strings"

	"github.com/ProtocolONE/auth1.protocol.one/internal/domain/entity"
	"github.com/ProtocolONE/auth1.protocol.one/internal/domain/repository"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/models"
	"github.com/globalsign/mgo/bson"
	"github.com/pkg/errors"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/facebook"
	"golang.org/x/oauth2/google"
	"golang.org/x/oauth2/twitch"
	"golang.org/x/oauth2/vk"
)

// AppIdentityProviderServiceInterface describes of methods for the AppIdentityProviderService.
type AppIdentityProviderServiceInterface interface {
	// Get return the identity provider by application and provider id.
	// Get(*models.Application, bson.ObjectId) *models.AppIdentityProvider
	// GetSpace(space *models.Space, id bson.ObjectId) *models.AppIdentityProvider

	// FindByType find and return list of identity providers by type.
	// FindByType(*models.Application, string) []*models.AppIdentityProvider
	// FindByTypeSpace(space *models.Space, connType string) []*models.AppIdentityProvider

	// FindByTypeAndName find and return list of identity provider by name and type.
	FindByTypeAndName(*models.Application, string, string) *models.AppIdentityProvider
	// FindByTypeAndNameSpace(space *models.Space, connType string, name string) *models.AppIdentityProvider

	// NormalizeSocialConnection fills in the default fields for social providers.
	// NormalizeSocialConnection(*models.AppIdentityProvider) error

	// GetAvailableTemplates return list of string with available social networks.
	GetAvailableTemplates() []string

	// GetAllTemplates returns a list of social providers with default values for each provider.
	GetAllTemplates() []*models.AppIdentityProvider

	// GetTemplate returns a social provider with default values.
	GetTemplate(string) (*models.AppIdentityProvider, error)

	// GetAuthUrl generates an authorization string for the social provider oauth2.
	GetAuthUrl(string, *models.AppIdentityProvider, interface{}) (string, error)

	// GetSocialProfile swaps the authorization code for an access token on a social network and gets a user profile in it.
	GetSocialProfile(context.Context, string, string, *models.AppIdentityProvider) (*models.UserIdentitySocial, error)
}

// AppIdentityProviderService is the AppIdentityProvider service.
type AppIdentityProviderService struct {
	spaces repository.SpaceRepository
}

var (
	ErrorInvalidSocialProviderName = "Invalid identity provider: %s"
	ErrorInvalidTemplate           = "Identity provider [%s] template not found"
	ErrorFuncNumberParameters      = "The number of parameters is not adapted"
)

// NewAppIdentityProviderService return new AppIdentityProvider service.
func NewAppIdentityProviderService(spaces repository.SpaceRepository) *AppIdentityProviderService {
	return &AppIdentityProviderService{spaces: spaces}
}

func (s AppIdentityProviderService) FindByTypeAndName(app *models.Application, connType string, name string) *models.AppIdentityProvider {
	space, err := s.spaces.FindByID(context.TODO(), entity.SpaceID(app.SpaceId.Hex()))
	if err != nil {
		panic(err)
	}
	for _, p := range space.IdentityProviders {
		if p.Name == name && string(p.Type) == connType {
			return &models.AppIdentityProvider{
				ID:                  bson.ObjectIdHex(string(p.ID)),
				Name:                p.Name,
				Type:                string(p.Type),
				DisplayName:         p.DisplayName,
				ClientID:            p.ClientID,
				ClientSecret:        p.ClientSecret,
				ClientScopes:        p.ClientScopes,
				EndpointAuthURL:     p.EndpointAuthURL,
				EndpointTokenURL:    p.EndpointTokenURL,
				EndpointUserInfoURL: p.EndpointUserInfoURL,
			}
		}
	}

	return nil
}

// func (s AppIdentityProviderService) NormalizeSocialConnection(ipc *models.AppIdentityProvider) error {
// 	template, err := s.GetTemplate(ipc.Name)
// 	if err != nil {
// 		return errors.Errorf(ErrorInvalidSocialProviderName, ipc.Name)
// 	}

// 	list := append(template.ClientScopes, ipc.ClientScopes...)
// 	keys := make(map[string]bool)
// 	var scopes []string
// 	for _, entry := range list {
// 		if _, value := keys[entry]; !value {
// 			keys[entry] = true
// 			scopes = append(scopes, entry)
// 		}
// 	}

// 	ipc.DisplayName = template.DisplayName
// 	ipc.EndpointAuthURL = template.EndpointAuthURL
// 	ipc.EndpointTokenURL = template.EndpointTokenURL
// 	ipc.EndpointUserInfoURL = template.EndpointUserInfoURL
// 	ipc.ClientScopes = scopes

// 	return nil
// }

func (s *AppIdentityProviderService) GetAvailableTemplates() []string {
	return []string{
		models.AppIdentityProviderNameFacebook,
		models.AppIdentityProviderNameTwitch,
		models.AppIdentityProviderNameGoogle,
		models.AppIdentityProviderNameVk,
	}
}

func (s *AppIdentityProviderService) GetAllTemplates() []*models.AppIdentityProvider {
	var list []*models.AppIdentityProvider
	for _, name := range s.GetAvailableTemplates() {
		template, _ := s.GetTemplate(name)
		list = append(list, template)
	}
	return list
}

func (s *AppIdentityProviderService) GetTemplate(name string) (*models.AppIdentityProvider, error) {
	switch name {
	case models.AppIdentityProviderNameFacebook:
		return s.getFacebookTemplate(), nil
	case models.AppIdentityProviderNameTwitch:
		return s.getTwitchTemplate(), nil
	case models.AppIdentityProviderNameGoogle:
		return s.getGoogleTemplate(), nil
	case models.AppIdentityProviderNameVk:
		return s.getVkTemplate(), nil
	}
	return nil, errors.Errorf(ErrorInvalidTemplate, name)
}

func (s *AppIdentityProviderService) getFacebookTemplate() *models.AppIdentityProvider {
	return &models.AppIdentityProvider{
		Type:                models.AppIdentityProviderTypeSocial,
		ClientScopes:        []string{"email", "user_birthday", "user_friends"},
		EndpointAuthURL:     facebook.Endpoint.AuthURL,
		EndpointTokenURL:    facebook.Endpoint.TokenURL,
		EndpointUserInfoURL: "https://graph.facebook.com/me?fields=id,name,first_name,last_name,email,birthday,picture&access_token=%s",
		Name:                models.AppIdentityProviderNameFacebook,
		DisplayName:         models.AppIdentityProviderDisplayNameFacebook,
	}
}

func (s *AppIdentityProviderService) getTwitchTemplate() *models.AppIdentityProvider {
	return &models.AppIdentityProvider{
		Type:                models.AppIdentityProviderTypeSocial,
		ClientScopes:        []string{"user_read", "channel_subscriptions"},
		EndpointAuthURL:     twitch.Endpoint.AuthURL,
		EndpointTokenURL:    twitch.Endpoint.TokenURL,
		EndpointUserInfoURL: "https://api.twitch.tv/kraken/user?client_id=r0elllpn5whuyf3et3pm6apqifn9yg&oauth_token=%s",
		Name:                models.AppIdentityProviderNameTwitch,
		DisplayName:         models.AppIdentityProviderDisplayNameTwitch,
	}
}

func (s *AppIdentityProviderService) getGoogleTemplate() *models.AppIdentityProvider {
	return &models.AppIdentityProvider{
		Type:                models.AppIdentityProviderTypeSocial,
		ClientScopes:        []string{"https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/userinfo.profile"},
		EndpointAuthURL:     google.Endpoint.AuthURL,
		EndpointTokenURL:    google.Endpoint.TokenURL,
		EndpointUserInfoURL: "https://www.googleapis.com/oauth2/v1/userinfo?access_token=%s",
		Name:                models.AppIdentityProviderNameGoogle,
		DisplayName:         models.AppIdentityProviderDisplayNameGoogle,
	}
}

func (s *AppIdentityProviderService) getVkTemplate() *models.AppIdentityProvider {
	return &models.AppIdentityProvider{
		Type:                models.AppIdentityProviderTypeSocial,
		ClientScopes:        []string{"email", "friends"},
		EndpointAuthURL:     vk.Endpoint.AuthURL,
		EndpointTokenURL:    vk.Endpoint.TokenURL,
		EndpointUserInfoURL: "https://api.vk.com/method/users.get?fields=bdate,photo_50&v=5.92&access_token=%s",
		Name:                models.AppIdentityProviderNameVk,
		DisplayName:         models.AppIdentityProviderDisplayNameVk,
	}
}

func (s *AppIdentityProviderService) GetAuthUrl(domain string, ip *models.AppIdentityProvider, form interface{}) (string, error) {
	var buf bytes.Buffer
	buf.WriteString(ip.EndpointAuthURL)
	v := url.Values{
		"response_type": {"code"},
		"client_id":     {ip.ClientID},
		"redirect_uri":  {s.callbackUrl(domain, ip.Name)},
	}
	if len(ip.ClientScopes) > 0 {
		v.Set("scope", strings.Join(ip.ClientScopes, " "))
	}
	state, err := json.Marshal(form)
	if err != nil {
		return "", err
	}
	v.Set("state", base64.StdEncoding.EncodeToString(state))
	if strings.Contains(ip.EndpointAuthURL, "?") {
		buf.WriteByte('&')
	} else {
		buf.WriteByte('?')
	}
	buf.WriteString(v.Encode())
	return buf.String(), nil
}

func (s *AppIdentityProviderService) callbackUrl(domain, provider string) string {
	return fmt.Sprintf("%s/api/providers/%s/callback", domain, provider)
}

func (s *AppIdentityProviderService) GetSocialProfile(ctx context.Context, domain string, code string, ip *models.AppIdentityProvider) (*models.UserIdentitySocial, error) {
	rUrl := s.callbackUrl(domain, ip.Name)
	conf := &oauth2.Config{
		ClientID:     ip.ClientID,
		ClientSecret: ip.ClientSecret,
		Scopes:       ip.ClientScopes,
		RedirectURL:  rUrl,
		Endpoint: oauth2.Endpoint{
			AuthURL:  ip.EndpointAuthURL,
			TokenURL: ip.EndpointTokenURL,
		},
	}

	t, err := conf.Exchange(ctx, code)
	if err != nil {
		return nil, err
	}

	resp, err := http.Get(fmt.Sprintf(ip.EndpointUserInfoURL, url.QueryEscape(t.AccessToken)))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	uis := &models.UserIdentitySocial{
		Token: t.AccessToken,
		Email: fmt.Sprint(t.Extra("email")),
	}
	var f interface{}
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, err
	}

	m := f.(map[string]interface{})
	if _, err := parseResponse(ip.Name, m, uis); err != nil {
		return nil, err
	}

	return uis, nil
}

func parseResponse(name string, params ...interface{}) (result *models.UserIdentitySocial, err error) {
	funcs := map[string]interface{}{
		"facebook": parseResponseFacebook,
		"twitch":   parseResponseTwitch,
		"google":   parseResponseGoogle,
		"vk":       parseResponseVk,
	}
	f := reflect.ValueOf(funcs[name])
	if len(params) != f.Type().NumIn() {
		err = errors.New(ErrorFuncNumberParameters)
		return
	}
	in := make([]reflect.Value, len(params))
	for k, param := range params {
		in[k] = reflect.ValueOf(param)
	}
	result = reflect.Value(f.Call(in)[0]).Elem().Interface().(*models.UserIdentitySocial)
	return
}

func parseResponseFacebook(data map[string]interface{}, uis *models.UserIdentitySocial) interface{} {
	uis.ID = data["id"].(string)
	uis.Email = data["email"].(string)
	uis.Name = data["name"].(string)
	uis.FirstName = data["first_name"].(string)
	uis.LastName = data["last_name"].(string)
	uis.Birthday = data["birthday"].(string)
	uis.Picture = data["picture"].(map[string]interface{})["data"].(map[string]interface{})["url"].(string)

	if data["birthday"] != nil {
		uis.Birthday = data["birthday"].(string)
		bFull := regexp.MustCompile("([0-9]{1,2})/([0-9]{1,2})/([0-9]{4})")
		reFull := bFull.FindStringSubmatch(uis.Birthday)
		bShort := regexp.MustCompile("([0-9]{4})")
		reShort := bShort.FindStringSubmatch(uis.Birthday)

		if len(reFull) > 0 {
			if len(reFull[1]) == 1 {
				reFull[1] = fmt.Sprintf("0%s", reFull[1])
			}
			if len(reFull[2]) == 1 {
				reFull[2] = fmt.Sprintf("0%s", reFull[2])
			}
			uis.Birthday = fmt.Sprintf("%s-%s-%s", reFull[3], reFull[1], reFull[2])
		} else if len(reShort) > 0 {
			if len(reShort[1]) == 1 {
				reShort[1] = fmt.Sprintf("0%s", reShort[1])
			}
			if len(reShort[2]) == 1 {
				reShort[2] = fmt.Sprintf("0%s", reShort[2])
			}
			uis.Birthday = fmt.Sprintf("%s-01-01", reShort[1])
		}
	}
	return uis
}

func parseResponseTwitch(data map[string]interface{}, uis *models.UserIdentitySocial) interface{} {
	uis.ID = fmt.Sprintf("%.0f", data["_id"].(float64))
	uis.Email = data["email"].(string)
	uis.Name = data["name"].(string)
	uis.Picture = data["logo"].(string)

	return uis
}

func parseResponseGoogle(data map[string]interface{}, uis *models.UserIdentitySocial) interface{} {
	uis.ID = fmt.Sprintf("%.0f", data["id"])
	uis.Email = data["email"].(string)
	uis.Name = data["name"].(string)
	uis.FirstName = data["given_name"].(string)
	uis.LastName = data["family_name"].(string)
	uis.Picture = data["picture"].(string)

	return uis
}

func parseResponseVk(data map[string]interface{}, uis *models.UserIdentitySocial) interface{} {
	r := data["response"].([]interface{})[0].(map[string]interface{})
	uis.ID = fmt.Sprintf("%.0f", r["id"].(float64))
	uis.FirstName = r["first_name"].(string)
	uis.LastName = r["last_name"].(string)
	uis.Picture = r["photo_50"].(string)

	if r["bdate"] != nil {
		uis.Birthday = r["bdate"].(string)
		b := regexp.MustCompile("([0-9]{1,2}).([0-9]{1,2})(.([0-9]{4}))?")
		re := b.FindStringSubmatch(uis.Birthday)
		if len(re) > 0 && re[4] != "" {
			if len(re[1]) == 1 {
				re[1] = fmt.Sprintf("0%s", re[1])
			}
			if len(re[2]) == 1 {
				re[2] = fmt.Sprintf("0%s", re[2])
			}
			uis.Birthday = fmt.Sprintf("%s-%s-%s\r\n", re[4], re[2], re[1])
		}
	}
	return uis
}
