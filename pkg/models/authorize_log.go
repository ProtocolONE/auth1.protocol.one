package models

import (
	"auth-one-api/pkg/database"
	"github.com/labstack/echo"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

type (
	AuthorizeLog struct {
		ID          bson.ObjectId `bson:"_id" json:"id"`
		UserID      bson.ObjectId `bson:"user_id" json:"user_id"`
		Token       string        `bson:"token" json:"token"`
		UserAgentId bson.ObjectId `bson:"useragent_id" json:"useragent_id"`
		IpId        bson.ObjectId `bson:"ip_id" json:"ip_id"`
	}

	AuthorizeUserAgent struct {
		ID    bson.ObjectId `bson:"_id" json:"id"`
		Value string        `bson:"value" json:"value"`
	}

	AuthorizeUserIP struct {
		ID    bson.ObjectId `bson:"_id" json:"id"`
		Value string        `bson:"value" json:"value"`
	}
)

type AuthLogService struct {
	db *mgo.Database
}

func NewAuthLogService(h *database.Handler) *AuthLogService {
	return &AuthLogService{h.Session.DB(h.Name)}
}

func (s AuthLogService) Add(ctx echo.Context, user *User, token string) error {
	ua, err := s.addUserAgent(ctx.Request().UserAgent())
	if err != nil {
		return err
	}

	ip, err := s.addUserIP(ctx.RealIP())
	if err != nil {
		return err
	}

	l := AuthorizeLog{
		ID:          bson.NewObjectId(),
		UserID:      user.ID,
		Token:       token,
		UserAgentId: ua.ID,
		IpId:        ip.ID,
	}
	if err := s.db.C(database.TableAuthLog).Insert(l); err != nil {
		return err
	}

	return nil
}

func (s AuthLogService) addUserAgent(userAgent string) (*AuthorizeUserAgent, error) {
	a := &AuthorizeUserAgent{}
	q := s.db.C(database.TableUserAgent).Find(bson.D{{"value", userAgent}})
	c, err := q.Count()
	if err != nil {
		return nil, err
	}

	if c == 0 {
		a.ID = bson.NewObjectId()
		a.Value = userAgent
		if err := s.db.C(database.TableUserAgent).Insert(a); err != nil {
			return nil, err
		}
	} else {
		if err := q.One(&a); err != nil {
			return nil, err
		}
	}

	return a, nil
}

func (s AuthLogService) addUserIP(ip string) (*AuthorizeUserIP, error) {
	a := &AuthorizeUserIP{}
	q := s.db.C(database.TableUserIP).Find(bson.D{{"value", ip}})
	c, err := q.Count()
	if err != nil {
		return nil, err
	}

	if c == 0 {
		a.ID = bson.NewObjectId()
		a.Value = ip
		if err := s.db.C(database.TableUserIP).Insert(a); err != nil {
			return nil, err
		}
	} else {
		if err := q.One(&a); err != nil {
			return nil, err
		}
	}

	return a, nil
}
