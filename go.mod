module github.com/ProtocolONE/auth1.protocol.one

require (
	github.com/ProtocolONE/authone-jwt-verifier-golang v0.0.0-20190329122021-aa7178c82afb
	github.com/ProtocolONE/geoip-service v1.0.2
	github.com/ProtocolONE/mfa-service v0.1.1
	github.com/bmizerany/assert v0.0.0-20160611221934-b7ed37b82869
	github.com/boj/redistore v0.0.0-20180917114910-cd5dcc76aeff
	github.com/davecgh/go-spew v1.1.1
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/globalsign/mgo v0.0.0-20181015135952-eeefdecb41b8
	github.com/go-openapi/runtime v0.19.11
	github.com/go-openapi/strfmt v0.19.4
	github.com/go-redis/redis v6.15.2+incompatible
	github.com/google/uuid v1.1.1
	github.com/gorilla/websocket v1.4.2
	github.com/inconshreveable/mousetrap v1.0.0 // indirect
	github.com/jinzhu/copier v0.0.0-20180308034124-7e38e58719c3
	github.com/juju/zaputil v0.0.0-20190326175239-ef53049637ac
	github.com/kelseyhightower/envconfig v1.3.0
	github.com/labstack/echo-contrib v0.0.0-20190220224852-7fa08ffe9442
	github.com/labstack/echo/v4 v4.1.14
	github.com/labstack/gommon v0.3.0
	github.com/micro/go-micro v1.18.0
	github.com/micro/go-plugins v2.0.1-0.20200225142654-7203ed025b21+incompatible // indirect
	github.com/micro/go-plugins/client/selector/static v0.0.0-20200119172437-4fe21aa238fd
	github.com/micro/micro/v2 v2.2.0 // indirect
	github.com/ory/hydra-client-go v1.3.2
	github.com/pkg/errors v0.9.1
	github.com/spf13/cobra v0.0.3
	github.com/stretchr/testify v1.4.0
	github.com/xakep666/mongo-migrate v0.1.0
	go.uber.org/zap v1.13.0
	golang.org/x/crypto v0.0.0-20200221231518-2aa609cf4a9d
	golang.org/x/oauth2 v0.0.0-20191202225959-858c2ad4c8b6
	gopkg.in/go-playground/validator.v9 v9.31.0
	gopkg.in/gomail.v2 v2.0.0-20160411212932-81ebce5c23df
	gopkg.in/tomb.v2 v2.0.0-20161208151619-d5d1b5820637
)

replace github.com/hashicorp/consul => github.com/hashicorp/consul v1.5.1

replace github.com/gogo/protobuf => github.com/gogo/protobuf v1.3.0

go 1.13
