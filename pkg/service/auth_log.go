package service

import (
	"github.com/ProtocolONE/auth1.protocol.one/pkg/database"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/models"
	"github.com/globalsign/mgo"
	"github.com/globalsign/mgo/bson"
)

type AuthLogServiceInterface interface {
	Add(string, string, *models.User, string) error
}

type AuthLogService struct {
	db *mgo.Database
}

func NewAuthLogService(h database.Session) *AuthLogService {
	return &AuthLogService{db: h.DB("")}
}

func (s AuthLogService) Add(ipAddr string, userAgent string, user *models.User, token string) error {
	ua, err := s.addUserAgent(userAgent)
	if err != nil {
		return err
	}

	ip, err := s.addUserIP(ipAddr)
	if err != nil {
		return err
	}

	l := &models.AuthorizeLog{
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

func (s AuthLogService) addUserAgent(userAgent string) (*models.AuthorizeUserAgent, error) {
	a := &models.AuthorizeUserAgent{}
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

func (s AuthLogService) addUserIP(ip string) (*models.AuthorizeUserIP, error) {
	a := &models.AuthorizeUserIP{}
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
