package models

import (
	"auth-one-api/pkg/database"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/labstack/echo"
	"go.uber.org/zap/zapcore"
	"golang.org/x/oauth2"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
	"io/ioutil"
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"time"
)

type (
	UserIdentityService struct {
		db *mgo.Database
	}

	UserIdentity struct {
		ID         bson.ObjectId `bson:"_id" json:"id"`
		UserID     bson.ObjectId `bson:"user_id" json:"user_id"`
		AppID      bson.ObjectId `bson:"app_id" json:"app_id"`
		Connection string        `bson:"connection" json:"connection"`
		Provider   string        `bson:"provider" json:"provider" validate:"required"`
		ExternalID string        `bson:"external_id" json:"external_id"`
		Credential string        `bson:"credential" json:"-" validate:"required"`
		Email      string        `bson:"email" json:"email" validate:"required,email"`
		Username   string        `bson:"username" json:"username"`
		Name       string        `bson:"name" json:"name"`
		Picture    string        `bson:"picture" json:"picture"`
		Friends    []string      `bson:"friends" json:"friends"`
		CreatedAt  time.Time     `bson:"created_at" json:"created_at"`
		UpdatedAt  time.Time     `bson:"updated_at" json:"updated_at"`
	}

	UserIdentityConnection struct {
		ID                  bson.ObjectId
		AppID               bson.ObjectId
		Provider            string
		Connection          string
		IsSocial            bool
		ClientID            string
		ClientSecret        string
		ClientScopes        []string
		EndpointAuthURL     string
		EndpointTokenURL    string
		EndpointUserInfoURL string
	}

	UserIdentitySocial struct {
		ID        string `json:"id"`
		Name      string `json:"name"`
		FirstName string `json:"first_name"`
		LastName  string `json:"last_name"`
		Email     string `json:"email"`
		Birthday  string `json:"birthday"`
		Picture   string `json:"picture"`
		Token     string `json:"token"`
	}

	SocialSettings struct {
		LinkedTokenLength int `json:"linked_token_length"`
		LinkedTTL         int `json:"linked_token_ttl"`
	}
)

const (
	UserIdentityProviderPassword = "password"
	UserIdentityProviderSocial   = "social"
)

func (a *UserIdentity) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("ID", a.ID.String())
	enc.AddString("UserID", a.UserID.String())
	enc.AddString("AppID", a.AppID.String())
	enc.AddString("Connection", a.Connection)
	enc.AddString("Provider", a.Provider)
	enc.AddString("ExternalID", a.ExternalID)
	enc.AddString("Credential", a.Credential)
	enc.AddString("Email", a.Email)
	enc.AddString("Username", a.Username)
	enc.AddString("Name", a.Name)
	enc.AddString("Email", a.Email)
	enc.AddTime("CreatedAt", a.CreatedAt)
	enc.AddTime("UpdatedAt", a.UpdatedAt)

	return nil
}

func (a *UserIdentitySocial) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("ID", a.ID)
	enc.AddString("Name", a.Name)
	enc.AddString("Email", a.Email)

	return nil
}

func NewUserIdentityService(dbHandler *database.Handler) *UserIdentityService {
	return &UserIdentityService{dbHandler.Session.DB(dbHandler.Name)}
}

func (us UserIdentityService) Create(userIdentity *UserIdentity) error {
	if err := us.db.C(database.TableUserIdentity).Insert(userIdentity); err != nil {
		return err
	}

	return nil
}

func (us UserIdentityService) Update(userIdentity *UserIdentity) error {
	if err := us.db.C(database.TableUserIdentity).UpdateId(userIdentity.ID, userIdentity); err != nil {
		return err
	}

	return nil
}

func (us UserIdentityService) Get(app *Application, provider string, connection string, externalId string) (*UserIdentity, error) {
	ui := &UserIdentity{}
	err := us.db.C(database.TableUserIdentity).
		Find(bson.M{"app_id": app.ID, "provider": provider, "external_id": externalId}).
		One(&ui)

	if err != nil {
		return nil, err
	}

	return ui, nil
}

func (uic *UserIdentityConnection) GetAuthUrl(ctx echo.Context, form interface{}) (string, error) {
	rUrl := fmt.Sprintf("%s://%s/authorize/result", ctx.Scheme(), ctx.Request().Host)
	conf := &oauth2.Config{
		ClientID:     uic.ClientID,
		ClientSecret: uic.ClientSecret,
		Scopes:       uic.ClientScopes,
		RedirectURL:  rUrl,
		Endpoint: oauth2.Endpoint{
			AuthURL:  uic.EndpointAuthURL,
			TokenURL: uic.EndpointTokenURL,
		},
	}

	s, err := json.Marshal(form)
	if err != nil {
		return "", err
	}

	return conf.AuthCodeURL(base64.StdEncoding.EncodeToString(s), oauth2.AccessTypeOffline), nil
}

func (uic *UserIdentityConnection) GetClientProfile(ctx echo.Context) (*UserIdentitySocial, error) {
	rUrl := fmt.Sprintf("%s://%s/authorize/result", ctx.Scheme(), ctx.Request().Host)
	conf := &oauth2.Config{
		ClientID:     uic.ClientID,
		ClientSecret: uic.ClientSecret,
		Scopes:       uic.ClientScopes,
		RedirectURL:  rUrl,
		Endpoint: oauth2.Endpoint{
			AuthURL:  uic.EndpointAuthURL,
			TokenURL: uic.EndpointTokenURL,
		},
	}

	t, err := conf.Exchange(context.Background(), ctx.QueryParam("code"))
	if err != nil {
		return nil, err
	}

	resp, err := http.Get(fmt.Sprintf(uic.EndpointUserInfoURL, url.QueryEscape(t.AccessToken)))
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
	if _, err := parseResponse(uic.Connection, m, uis); err != nil {
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
