package service

import (
	"net/http"
	"time"

	"github.com/ProtocolONE/auth1.protocol.one/pkg/database"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/models"
	"github.com/globalsign/mgo"
	"github.com/globalsign/mgo/bson"
	"github.com/labstack/echo/v4"
)

type AuthActionType string

const (
	ActionReg  AuthActionType = "register"
	ActionAuth AuthActionType = "auth"
)

// AuthorizeLog describes a records for storing the user authorizations log.
type AuthorizeLog struct {
	// ID is the record id.
	ID bson.ObjectId `bson:"_id" json:"id"`

	// Timestamp in UTC
	Timestamp time.Time `bson:"timestamp" json:"timestamp"`

	// ActionType is auth action registration or authentication
	ActionType AuthActionType `bson:"action_type" json:"action_type"`

	// AppID is application id
	AppID bson.ObjectId `bson:"app_id" json:"app_id"`

	// AppName
	AppName string `bson:"app_name" json:"app_name"`

	// UserID is the user id.
	UserID bson.ObjectId `bson:"user_id" json:"user_id"`

	// UserIdentityID is the user identity id.
	UserIdentityID bson.ObjectId `bson:"user_identity_id" json:"user_identity_id"`

	// ProviderID is external identity provider id
	ProviderID bson.ObjectId `bson:"provider_id json:"provider_id"`

	// ProviderName is external identity provider name
	ProviderName string `bson:"provider_name" json:"provider_name"`

	// Referer is browser referer page
	Referer string `bson:"referer" json:"referer"`

	// UserAgent is client useragent
	UserAgent string `bson:"useragent" json:"useragent"`

	// IP is user ip
	IP string `bson:"ip" json:"ip"`

	// ClientTime time from http Date header
	ClientTime time.Time `bson:"client_time" json:"client_time"`
}

// AuthLogServiceInterface describes of methods for the AuthLog service.
type AuthLogServiceInterface interface {
	// Add adds an authorization log for the user.
	Add(reqctx echo.Context, kind AuthActionType, identity *models.UserIdentity, app *models.Application, provider *models.AppIdentityProvider) error
	Get(userId string, count int, from string) ([]*AuthorizeLog, error)
}

// AuthLogService is the AuthLog service.
type AuthLogService struct {
	db *mgo.Database
}

// NewAuthLogService return new AuthLog service.
func NewAuthLogService(h database.MgoSession) *AuthLogService {
	return &AuthLogService{db: h.DB("")}
}

func (s AuthLogService) Add(reqctx echo.Context, kind AuthActionType, identity *models.UserIdentity, app *models.Application, provider *models.AppIdentityProvider) error {
	ctime, err := http.ParseTime(reqctx.Request().Header.Get("Date"))
	if err != nil {
		// TODO log error
		ctime = time.Unix(0, 0)
	}

	record := &AuthorizeLog{
		ID:         bson.NewObjectId(),
		Timestamp:  time.Now().UTC(),
		ActionType: kind,
		// app params
		AppID:   app.ID,
		AppName: app.Name,
		// user identity
		UserID:         identity.UserID,
		UserIdentityID: identity.ID,
		// request context
		Referer:    reqctx.Request().Referer(),
		UserAgent:  reqctx.Request().UserAgent(),
		IP:         reqctx.RealIP(),
		ClientTime: ctime,
	}
	// identity provider
	if provider != nil {
		record.ProviderID = provider.ID
		record.ProviderName = provider.Name
	}

	return s.db.C(database.TableAuthLog).Insert(record)
}

func (s AuthLogService) Get(userId string, count int, from string) ([]*AuthorizeLog, error) {
	query := bson.M{
		"user_id": bson.ObjectIdHex(userId),
	}
	if from != "" {
		query["_id"] = bson.M{"$gt": bson.ObjectIdHex(from)}
	}

	var res []*AuthorizeLog
	if err := s.db.C(database.TableAuthLog).Find(query).Limit(count).All(&res); err != nil {
		return nil, err
	}

	return res, nil
}
