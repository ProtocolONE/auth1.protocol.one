package models

import (
	"github.com/dgrijalva/jwt-go"
	"github.com/go-redis/redis"
	"github.com/labstack/gommon/random"
	"gopkg.in/mgo.v2/bson"
	"time"
)

type (
	AuthToken struct {
		AccessToken  string `json:"access_token,omitempty"`
		ExpiresIn    int64  `json:"expires_in,omitempty"`
		RefreshToken string `json:"refresh_token,omitempty"`
	}

	OneTimeTokenService struct {
		*redis.Client
	}

	OneTimeTokenForm struct {
		ClientId string `json:"client_id" form:"client_id" validate:"required"`
		Token    string `json:"token" form:"token" validate:"required"`
	}

	OneTimeToken struct {
		Token string `json:"token,omitempty"`
		Code  string `json:"code,omitempty"`
	}

	JwtTokenService struct {
		*JwtSettings
	}

	JwtSettings struct {
		Key    []byte
		TTL    int
		Method jwt.SigningMethod
	}

	JwtClaim struct {
		UserId         bson.ObjectId
		Email          string
		EmailConfirmed bool
		Nickname       string
		jwt.StandardClaims
	}

	RefreshTokenService struct {
		*RefreshTokenSettings
	}

	RefreshTokenSettings struct {
		Length int
		TTL    int
	}

	RefreshToken struct {
		Value     string
		TTL       int
		UserAgent string
		IP        string
	}

	RefreshTokenForm struct {
		ClientId string `json:"client_id" form:"client_id" validate:"required"`
		Token    string `json:"token" form:"token" validate:"required"`
	}
)

func NewJwtTokenService(s *JwtSettings) *JwtTokenService {
	return &JwtTokenService{s}
}

func (ts JwtTokenService) Create(u *User) (string, error) {
	claims := &JwtClaim{
		UserId:         u.ID,
		Email:          u.Email,
		EmailConfirmed: false,
		Nickname:       "",
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: int64(ts.TTL),
			Issuer:    string(u.ID),
		},
	}

	t := jwt.NewWithClaims(ts.Method, claims)
	return t.SignedString(ts.Key)
}

func NewRefreshTokenService(s *RefreshTokenSettings) *RefreshTokenService {
	return &RefreshTokenService{s}
}

func (rts RefreshTokenService) Create(ua string, ip string) *RefreshToken {
	return &RefreshToken{
		Value:     random.New().String(uint8(rts.Length)),
		TTL:       rts.TTL,
		UserAgent: ua,
		IP:        ip,
	}
}

func NewOneTimeTokenService(r *redis.Client) *OneTimeTokenService {
	return &OneTimeTokenService{r}
}

func (os *OneTimeTokenService) Create(length int, ttl int, charsets string) string {
	ott := random.New().String(uint8(length), charsets)
	os.Set("", ott, time.Duration(ttl)*time.Second)
	return ott
}
