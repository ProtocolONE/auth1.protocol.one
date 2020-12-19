package service

import (
	"context"
	"net/http"
	"time"

	"github.com/ProtocolONE/auth1.protocol.one/internal/domain/entity"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/appcore/log"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/database"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/models"
	geo "github.com/ProtocolONE/geoip-service/pkg/proto"
	"github.com/globalsign/mgo"
	"github.com/globalsign/mgo/bson"
	"github.com/labstack/echo/v4"
	"github.com/micro/go-micro/client"
	"github.com/pkg/errors"
	"go.uber.org/zap"
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

	// DeviceID is unique device identifier (special cookie for browser)
	DeviceID string `bson:"device_id" json:"device_id"`

	// IP is user ip
	IP string `bson:"ip" json:"ip"`

	// IPInfo is geo2ip info
	IPInfo IPInfo `bson:"ip_info" json:"ip_info"`

	// ClientTime time from http Date header
	ClientTime time.Time `bson:"client_time" json:"client_time"`
}

type IPInfo struct {
	Country     string   `bson:"country" json:"country"`
	City        string   `bson:"city" json:"city"`
	Subdivision []string `bson:"subdivision" json:"subdivision"`
}

type GeoIp interface {
	GetIpData(ctx context.Context, in *geo.GeoIpDataRequest, opts ...client.CallOption) (*geo.GeoIpDataResponse, error)
}

// AuthLogServiceInterface describes of methods for the AuthLog service.
type AuthLogServiceInterface interface {
	// Add adds an authorization log for the user.
	Add(reqctx echo.Context, kind AuthActionType, identity *models.UserIdentity, app *models.Application, provider *entity.IdentityProvider) error
	Get(userId string, count int, from string) ([]*AuthorizeLog, error)
	GetByDevice(deviceID string, count int, from string) ([]*AuthorizeLog, error)
}

// AuthLogService is the AuthLog service.
type AuthLogService struct {
	db  *mgo.Database
	geo GeoIp
}

// NewAuthLogService return new AuthLog service.
func NewAuthLogService(h database.MgoSession, geo GeoIp) *AuthLogService {
	return &AuthLogService{db: h.DB(""), geo: geo}
}

func (s AuthLogService) Add(reqctx echo.Context, kind AuthActionType, identity *models.UserIdentity, app *models.Application, provider *entity.IdentityProvider) error {
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
		DeviceID:   GetDeviceID(reqctx),
		ClientTime: ctime,
	}
	// identity provider
	if provider != nil {
		record.ProviderID = bson.ObjectIdHex(string(provider.ID))
		record.ProviderName = provider.Name
	}

	ipinfo, err := s.getIPInfo(record.IP)
	if err != nil {
		log.Error(reqctx.Request().Context(), "can't get geoip info", zap.Error(err))
	}
	record.IPInfo = ipinfo

	return s.db.C(database.TableAuthLog).Insert(record)
}

func (s *AuthLogService) getIPInfo(ip string) (ipinfo IPInfo, err error) {
	georesp, err := s.geo.GetIpData(context.TODO(), &geo.GeoIpDataRequest{IP: ip})
	if err != nil {
		return ipinfo, err
	}

	if georesp == nil {
		return ipinfo, errors.New("no repsonse")
	}

	city := georesp.GetCity()
	if city != nil {
		names := city.GetNames()
		if names != nil {
			ipinfo.City = names["en"]
		}
	}
	country := georesp.GetCountry()
	if country != nil {
		names := country.GetNames()
		if names != nil {
			ipinfo.Country = names["en"]
		}
	}
	for _, sub := range georesp.GetSubdivisions() {
		names := sub.GetNames()
		if names != nil {
			ipinfo.Subdivision = append(ipinfo.Subdivision, names["en"])
		}

	}
	return ipinfo, nil
}

func (s AuthLogService) Get(userId string, count int, from string) ([]*AuthorizeLog, error) {
	query := bson.M{
		"user_id": bson.ObjectIdHex(userId),
	}
	if from != "" {
		query["_id"] = bson.M{"$gt": bson.ObjectIdHex(from)}
	}

	var res []*AuthorizeLog
	if err := s.db.C(database.TableAuthLog).Find(query).Sort("-_id").Limit(count).All(&res); err != nil {
		return nil, err
	}

	return res, nil
}

func (s AuthLogService) GetByDevice(deviceID string, count int, from string) ([]*AuthorizeLog, error) {
	query := bson.M{
		"device_id": deviceID,
	}
	if from != "" {
		query["_id"] = bson.M{"$gt": bson.ObjectIdHex(from)}
	}

	var res []*AuthorizeLog
	if err := s.db.C(database.TableAuthLog).Find(query).Sort("-_id").Limit(count).All(&res); err != nil {
		return nil, err
	}

	return res, nil
}
