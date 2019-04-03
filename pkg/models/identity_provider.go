package models

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/database"
	"github.com/globalsign/mgo"
	"github.com/globalsign/mgo/bson"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap/zapcore"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/facebook"
	"golang.org/x/oauth2/google"
	"golang.org/x/oauth2/twitch"
	"golang.org/x/oauth2/vk"
	"io/ioutil"
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"strings"
)

var (
	AppIdentityProviderTypePassword = "password"
	AppIdentityProviderTypeSocial   = "social"

	AppIdentityProviderNameDefault  = "initial"
	AppIdentityProviderNameFacebook = "facebook"
	AppIdentityProviderNameTwitch   = "twitch"
	AppIdentityProviderNameGoogle   = "google"
	AppIdentityProviderNameVk       = "vk"
)

type AppIdentityProviderService struct {
	db *mgo.Database
}

type AppIdentityProvider struct {
	ID                  bson.ObjectId `bson:"_id" json:"id"`
	ApplicationID       bson.ObjectId `bson:"app_id" json:"application_id"`
	DisplayName         string        `bson:"display_name" json:"display_name"`
	Name                string        `bson:"name" json:"name"`
	Type                string        `bson:"type" json:"type"`
	ClientID            string        `bson:"client_id" json:"client_id"`
	ClientSecret        string        `bson:"client_secret" json:"client_secret"`
	ClientScopes        []string      `bson:"client_scopes" json:"client_scopes"`
	EndpointAuthURL     string        `bson:"endpoint_auth_url" json:"endpoint_auth_url"`
	EndpointTokenURL    string        `bson:"endpoint_token_url" json:"endpoint_token_url"`
	EndpointUserInfoURL string        `bson:"endpoint_userinfo_url" json:"endpoint_userinfo_url"`
}

func (ipc *AppIdentityProvider) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("ID", ipc.ID.String())
	enc.AddString("ApplicationID", ipc.ApplicationID.String())
	enc.AddString("DisplayName", ipc.DisplayName)
	enc.AddString("Name", ipc.Name)
	enc.AddString("Type", ipc.Type)
	enc.AddString("ClientID", ipc.ClientID)
	enc.AddString("ClientSecret", ipc.ClientSecret)
	enc.AddReflected("ClientScopes", ipc.ClientScopes)
	enc.AddString("EndpointAuthURL", ipc.EndpointAuthURL)
	enc.AddString("EndpointTokenURL", ipc.EndpointTokenURL)
	enc.AddString("EndpointUserInfoURL", ipc.EndpointUserInfoURL)

	return nil
}

func NewAppIdentityProviderService(dbHandler *mgo.Session) *AppIdentityProviderService {
	return &AppIdentityProviderService{db: dbHandler.DB("")}
}

func (ipcs AppIdentityProviderService) Create(ipc *AppIdentityProvider) error {
	if err := ipcs.db.C(database.TableAppIdentityProvider).Insert(ipc); err != nil {
		return err
	}
	return nil
}

func (ipcs AppIdentityProviderService) Update(ipc *AppIdentityProvider) error {
	if err := ipcs.db.C(database.TableAppIdentityProvider).UpdateId(ipc.ID, ipc); err != nil {
		return err
	}
	return nil
}

func (ipcs AppIdentityProviderService) Get(id bson.ObjectId) (*AppIdentityProvider, error) {
	ipc := &AppIdentityProvider{}
	if err := ipcs.db.C(database.TableAppIdentityProvider).
		FindId(id).
		One(&ipc); err != nil {
		return nil, err
	}

	return ipc, nil
}

func (ipcs AppIdentityProviderService) FindByType(app *Application, connType string) ([]AppIdentityProvider, error) {
	var ipc []AppIdentityProvider
	err := ipcs.db.C(database.TableAppIdentityProvider).
		Find(bson.M{"app_id": app.ID, "type": connType}).
		All(&ipc)

	if err != nil {
		return nil, err
	}

	return ipc, nil
}

func (ipcs AppIdentityProviderService) FindByTypeAndName(app *Application, connType string, name string) (*AppIdentityProvider, error) {
	ipc := &AppIdentityProvider{}
	err := ipcs.db.C(database.TableAppIdentityProvider).
		Find(bson.M{"app_id": app.ID, "type": connType, "name": name}).
		One(&ipc)

	if err != nil {
		return nil, err
	}

	return ipc, nil
}

func (ipcs AppIdentityProviderService) NormalizeSocialConnection(ipc *AppIdentityProvider) error {
	template, err := ipcs.GetTemplate(ipc.Name)
	if err != nil {
		return errors.New("Invalid identity provider" + ipc.Name)
	}

	list := append(template.ClientScopes, ipc.ClientScopes...)
	keys := make(map[string]bool)
	var scopes []string
	for _, entry := range list {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			scopes = append(scopes, entry)
		}
	}

	ipc.DisplayName = template.DisplayName
	ipc.EndpointAuthURL = template.EndpointAuthURL
	ipc.EndpointTokenURL = template.EndpointTokenURL
	ipc.EndpointUserInfoURL = template.EndpointUserInfoURL
	ipc.ClientScopes = scopes

	return nil
}

func (ipcs *AppIdentityProviderService) GetAvailableTemplates() []string {
	return []string{
		AppIdentityProviderNameFacebook,
		AppIdentityProviderNameTwitch,
		AppIdentityProviderNameGoogle,
		AppIdentityProviderNameVk,
	}
}

func (ipcs *AppIdentityProviderService) GetAllTemplates() []*AppIdentityProvider {
	var list []*AppIdentityProvider
	for _, name := range ipcs.GetAvailableTemplates() {
		template, _ := ipcs.GetTemplate(name)
		list = append(list, template)
	}
	return list
}

func (ipcs *AppIdentityProviderService) GetTemplate(name string) (*AppIdentityProvider, error) {
	switch name {
	case AppIdentityProviderNameFacebook:
		return ipcs.getFacebookTemplate(), nil
	case AppIdentityProviderNameTwitch:
		return ipcs.getTwitchTemplate(), nil
	case AppIdentityProviderNameGoogle:
		return ipcs.getGoogleTemplate(), nil
	case AppIdentityProviderNameVk:
		return ipcs.getVkTemplate(), nil
	}
	return nil, errors.New(fmt.Sprintf("identity provider [%s] template not found", name))
}

func (ipcs *AppIdentityProviderService) getFacebookTemplate() *AppIdentityProvider {
	return &AppIdentityProvider{
		Type:                AppIdentityProviderTypeSocial,
		ClientScopes:        []string{"email", "user_birthday", "user_friends"},
		EndpointAuthURL:     facebook.Endpoint.AuthURL,
		EndpointTokenURL:    facebook.Endpoint.TokenURL,
		EndpointUserInfoURL: "https://graph.facebook.com/me?fields=id,name,first_name,last_name,email,birthday,picture&access_token=%s",
		Name:                AppIdentityProviderNameFacebook,
	}
}

func (ipcs *AppIdentityProviderService) getTwitchTemplate() *AppIdentityProvider {
	return &AppIdentityProvider{
		Type:                AppIdentityProviderTypeSocial,
		ClientScopes:        []string{"user_read", "channel_subscriptions"},
		EndpointAuthURL:     twitch.Endpoint.AuthURL,
		EndpointTokenURL:    twitch.Endpoint.TokenURL,
		EndpointUserInfoURL: "https://api.twitch.tv/kraken/user?client_id=r0elllpn5whuyf3et3pm6apqifn9yg&oauth_token=%s",
		Name:                AppIdentityProviderNameTwitch,
	}
}

func (ipcs *AppIdentityProviderService) getGoogleTemplate() *AppIdentityProvider {
	return &AppIdentityProvider{
		Type:                AppIdentityProviderTypeSocial,
		ClientScopes:        []string{"https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/userinfo.profile"},
		EndpointAuthURL:     google.Endpoint.AuthURL,
		EndpointTokenURL:    google.Endpoint.TokenURL,
		EndpointUserInfoURL: "https://www.googleapis.com/oauth2/v1/userinfo?access_token=%s",
		Name:                AppIdentityProviderNameGoogle,
	}
}

func (ipcs *AppIdentityProviderService) getVkTemplate() *AppIdentityProvider {
	return &AppIdentityProvider{
		Type:                AppIdentityProviderTypeSocial,
		ClientScopes:        []string{"email", "friends"},
		EndpointAuthURL:     vk.Endpoint.AuthURL,
		EndpointTokenURL:    vk.Endpoint.TokenURL,
		EndpointUserInfoURL: "https://api.vk.com/method/users.get?fields=bdate,photo_50&v=5.92&access_token=%s",
		Name:                AppIdentityProviderNameVk,
	}
}

func (ipc *AppIdentityProvider) GetAuthUrl(ctx echo.Context, form interface{}) (string, error) {
	var buf bytes.Buffer
	buf.WriteString(ipc.EndpointAuthURL)
	v := url.Values{
		"response_type": {"code"},
		"client_id":     {ipc.ClientID},
		"redirect_uri":  {fmt.Sprintf("%s://%s/authorize/result", ctx.Scheme(), ctx.Request().Host)},
	}
	if len(ipc.ClientScopes) > 0 {
		v.Set("scope", strings.Join(ipc.ClientScopes, " "))
	}
	state, err := json.Marshal(form)
	if err != nil {
		return "", err
	}
	v.Set("state", base64.StdEncoding.EncodeToString(state))
	if strings.Contains(ipc.EndpointAuthURL, "?") {
		buf.WriteByte('&')
	} else {
		buf.WriteByte('?')
	}
	buf.WriteString(v.Encode())
	return buf.String(), nil
}

func (ipcs *AppIdentityProviderService) GetSocialProfile(ctx echo.Context, ip *AppIdentityProvider) (*UserIdentitySocial, error) {
	rUrl := fmt.Sprintf("%s://%s/authorize/result", ctx.Scheme(), ctx.Request().Host)
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

	t, err := conf.Exchange(ctx.Request().Context(), ctx.QueryParam("code"))
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

	uis := &UserIdentitySocial{
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

func parseResponse(name string, params ...interface{}) (result *UserIdentitySocial, err error) {
	funcs := map[string]interface{}{
		"facebook": parseResponseFacebook,
		"twitch":   parseResponseTwitch,
		"google":   parseResponseGoogle,
		"vk":       parseResponseVk,
	}
	f := reflect.ValueOf(funcs[name])
	if len(params) != f.Type().NumIn() {
		err = errors.New("The number of params is not adapted.")
		return
	}
	in := make([]reflect.Value, len(params))
	for k, param := range params {
		in[k] = reflect.ValueOf(param)
	}
	result = reflect.Value(f.Call(in)[0]).Elem().Interface().(*UserIdentitySocial)
	return
}

func parseResponseFacebook(data map[string]interface{}, uis *UserIdentitySocial) interface{} {
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

func parseResponseTwitch(data map[string]interface{}, uis *UserIdentitySocial) interface{} {
	uis.ID = fmt.Sprintf("%.0f", data["_id"].(float64))
	uis.Email = data["email"].(string)
	uis.Name = data["name"].(string)
	uis.Picture = data["logo"].(string)

	return uis
}

func parseResponseGoogle(data map[string]interface{}, uis *UserIdentitySocial) interface{} {
	uis.ID = fmt.Sprintf("%.0f", data["id"])
	uis.Email = data["email"].(string)
	uis.Name = data["name"].(string)
	uis.FirstName = data["given_name"].(string)
	uis.LastName = data["family_name"].(string)
	uis.Picture = data["picture"].(string)

	return uis
}

func parseResponseVk(data map[string]interface{}, uis *UserIdentitySocial) interface{} {
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
