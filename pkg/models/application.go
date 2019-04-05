package models

import (
	"github.com/ProtocolONE/auth1.protocol.one/pkg/database"
	"github.com/dgrijalva/jwt-go"
	"github.com/globalsign/mgo"
	"github.com/globalsign/mgo/bson"
	"github.com/pkg/errors"
	"go.uber.org/zap/zapcore"
	"time"
)

type ApplicationService struct {
	db *mgo.Database
}

type Application struct {
	ID               bson.ObjectId `bson:"_id" json:"id"`
	SpaceId          bson.ObjectId `bson:"space_id" json:"space_id"`
	Name             string        `bson:"name" json:"name" validate:"required"`
	Description      string        `bson:"description" json:"description"`
	IsActive         bool          `bson:"is_active" json:"is_active"`
	CreatedAt        time.Time     `bson:"created_at" json:"-"`
	UpdatedAt        time.Time     `bson:"updated_at" json:"-"`
	AuthSecret       string        `bson:"auth_secret" json:"auth_secret" validate:"required"`
	AuthRedirectUrls []string      `bson:"auth_redirect_urls" json:"auth_redirect_urls" validate:"required"`
	HasSharedUsers   bool          `bson:"has_shared_users" json:"has_shared_users"`
}

func (a *Application) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("ID", a.ID.String())
	enc.AddString("SpaceId", a.SpaceId.String())
	enc.AddString("Name", a.Name)
	enc.AddString("Description", a.Description)
	enc.AddBool("IsActive", a.IsActive)
	enc.AddTime("CreatedAt", a.CreatedAt)
	enc.AddTime("UpdatedAt", a.UpdatedAt)
	enc.AddBool("HasSharedUsers", a.HasSharedUsers)

	return nil
}

func NewApplicationService(dbHandler *mgo.Session) *ApplicationService {
	return &ApplicationService{db: dbHandler.DB("")}

}

func (s ApplicationService) Create(app *Application) error {
	if err := s.db.C(database.TableApplication).Insert(app); err != nil {
		return err
	}

	return nil
}

func (s ApplicationService) Update(app *Application) error {
	if err := s.db.C(database.TableApplication).UpdateId(app.ID, app); err != nil {
		return err
	}

	return nil
}

func (s ApplicationService) Get(id bson.ObjectId) (*Application, error) {
	a := &Application{}
	err := s.db.C(database.TableApplication).
		FindId(id).
		One(&a)

	if err != nil {
		return nil, errors.Wrapf(err, "Unable to load application with id %s", id.String())
	}

	return a, nil
}

func (s ApplicationService) SetPasswordSettings(app *Application, ps *PasswordSettings) error {
	if err := s.db.C(database.TableAppPasswordSettings).Find(bson.M{"app_id": app.ID}).One(&PasswordSettings{}); err == mgo.ErrNotFound {
		if err := s.db.C(database.TableAppPasswordSettings).Insert(ps); err != nil {
			return err
		}
	} else {
		if err := s.db.C(database.TableAppPasswordSettings).Update(bson.M{"app_id": app.ID}, bson.M{"$set": ps}); err != nil {
			return err
		}
	}

	return nil
}

func (s ApplicationService) GetPasswordSettings(app *Application) (*PasswordSettings, error) {
	ps := &PasswordSettings{}
	err := s.db.C(database.TableAppPasswordSettings).
		Find(bson.M{"app_id": app.ID}).
		One(&ps)

	if err != nil {
		return nil, errors.Wrapf(err, "Unable to load password settings for app %s", app.ID)
	}

	return ps, nil
}

func (s ApplicationService) LoadAuthTokenSettings() (*AuthTokenSettings, error) {
	return &AuthTokenSettings{
		JwtKey:        []byte("k33)%(7cltD:q.N4AyuXfjAuK{zO,nzP"),
		JwtMethod:     jwt.SigningMethodHS256,
		JwtTTL:        3600,
		RefreshLength: 512,
		RefreshTTL:    86400,
	}, nil
}

func (s ApplicationService) LoadSessionSettings() (*CookieSettings, error) {
	return &CookieSettings{
		Name: "X-AUTH-ONE-TOKEN",
		TTL:  3600,
	}, nil
}

func (s ApplicationService) LoadSocialSettings() (*SocialSettings, error) {
	return &SocialSettings{
		LinkedTokenLength: 128,
		LinkedTTL:         3600,
	}, nil
}

func (s ApplicationService) LoadMfaConnection(connection string) ([]*MfaConnection, error) {
	conn := []*MfaConnection{
		{
			Name:    "Application",
			Type:    "otp",
			Channel: "auth1",
		},
	}
	return conn, nil
}
