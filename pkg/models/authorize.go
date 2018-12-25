package models

import (
	"auth-one-api/pkg/database"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

type (
	CaptchaRequiredError CommonError

	AuthorizeForm struct {
		ClientId    string `json:"client_id" form:"client_id" validate:"required"`
		Connection  string `json:"connection" form:"connection" validate:"required"`
		RedirectUri string `json:"redirect_uri" form:"redirect_uri" validate:"required"`
		State       string `json:"state" form:"state" validate:"required"`
	}

	AuthorizeResultForm struct {
		ClientId   string `json:"client_id" form:"client_id" validate:"required"`
		Connection string `json:"connection" form:"connection" validate:"required"`
		OTT        string `json:"auth_one_ott" form:"auth_one_ott" validate:"required"`
		WsUrl      string `json:"ws_url" form:"ws_url"`
	}

	AuthorizeLog struct {
		ID          bson.ObjectId `json:"id"`
		Token       string        `json:"token"`
		UserAgentId bson.ObjectId `json:"useragent_id"`
		IpId        bson.ObjectId `json:"ip_id"`
	}

	AuthorizeUserAgent struct {
		ID    bson.ObjectId
		Value string
	}

	AuthorizeUserIP struct {
		ID    bson.ObjectId
		Value string
	}
)

func (m CaptchaRequiredError) Error() string {
	return m.Message
}

func (m *CaptchaRequiredError) GetCode() string {
	return m.Code
}

func (m *CaptchaRequiredError) GetMessage() string {
	return m.Message
}

type AuthLogService struct {
	db *mgo.Database
}

func NewAuthLogService(h *database.Handler) *AuthLogService {
	return &AuthLogService{h.Session.DB(h.Name)}
}

func (s AuthLogService) Add(rt *RefreshToken) error {
	ua, err := s.addUserAgent(rt.UserAgent)
	if err != nil {
		return err
	}

	ip, err := s.addUserIP(rt.IP)
	if err != nil {
		return err
	}

	l := AuthorizeLog{
		ID:          bson.NewObjectId(),
		Token:       rt.Value,
		UserAgentId: ua.ID,
		IpId:        ip.ID,
	}
	if err := s.db.C(database.TableAuthLog).Insert(l); err != nil {
		return err
	}

	return nil
}

func (s AuthLogService) addUserAgent(ua string) (*AuthorizeUserAgent, error) {
	a := &AuthorizeUserAgent{}
	q := s.db.C(database.TableUserAgent).Find(bson.D{{"value", ua}})
	c, err := q.Count()
	if err != nil {
		return nil, err
	}

	if c == 0 {
		a.ID = bson.NewObjectId()
		a.Value = ua
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
