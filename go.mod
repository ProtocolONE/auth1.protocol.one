module github.com/ProtocolONE/auth1.protocol.one

require (
	github.com/ProtocolONE/authone-jwt-verifier-golang v0.0.0-20190329122021-aa7178c82afb
	github.com/ProtocolONE/mfa-service v0.1.1
	github.com/alicebob/gopher-json v0.0.0-20180125190556-5a6b3ba71ee6 // indirect
	github.com/alicebob/miniredis v2.5.0+incompatible
	github.com/bmizerany/assert v0.0.0-20160611221934-b7ed37b82869
	github.com/boj/redistore v0.0.0-20180917114910-cd5dcc76aeff
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/elliotchance/redismock v1.5.1
	github.com/globalsign/mgo v0.0.0-20181015135952-eeefdecb41b8
	github.com/go-openapi/runtime v0.19.0
	github.com/go-openapi/strfmt v0.19.0
	github.com/go-openapi/swag v0.19.0
	github.com/go-redis/redis v6.15.2+incompatible
	github.com/golang/oauth2 v0.0.0-20181203162652-d668ce993890
	github.com/golang/protobuf v1.3.2
	github.com/google/uuid v1.1.1
	github.com/gorilla/securecookie v1.1.1
	github.com/gorilla/sessions v1.1.3
	github.com/ianlancetaylor/demangle v0.0.0-20181102032728-5e5cf60278f6 // indirect
	github.com/jinzhu/copier v0.0.0-20180308034124-7e38e58719c3
	github.com/juju/mgosession v1.0.0 // indirect
	github.com/kelseyhightower/envconfig v1.3.0
	github.com/kidstuff/mongostore v0.0.0-20181113001930-e650cd85ee4b
	github.com/labstack/echo-contrib v0.0.0-20190220224852-7fa08ffe9442
	github.com/labstack/echo/v4 v4.2.2
	github.com/labstack/gommon v0.3.0
	github.com/micro/go-micro v1.18.0
	github.com/micro/go-plugins v1.5.1
	github.com/ory/hydra v0.0.0-20190418080013-9c6e4c120c12
	github.com/pkg/errors v0.8.1
	github.com/sirupsen/logrus v1.4.2
	github.com/spf13/cobra v0.0.3
	github.com/spf13/viper v1.3.2
	github.com/stretchr/testify v1.4.0
	github.com/xakep666/mongo-migrate v0.1.0
	github.com/yuin/gopher-lua v0.0.0-20190206043414-8bfc7677f583 // indirect
	go.uber.org/zap v1.12.0
	golang.org/x/crypto v0.0.0-20200820211705-5c72a883971a
	golang.org/x/oauth2 v0.0.0-20190604053449-0f29369cfe45
	gopkg.in/go-playground/validator.v9 v9.30.0
	gopkg.in/gomail.v2 v2.0.0-20160411212932-81ebce5c23df
	gopkg.in/mgo.v2 v2.0.0-20180705113604-9856a29383ce
	gopkg.in/tomb.v2 v2.0.0-20161208151619-d5d1b5820637
	gopkg.in/yaml.v1 v1.0.0-20140924161607-9f9df34309c0 // indirect
	gopkg.in/yaml.v2 v2.2.4
)

replace (
	github.com/gogo/protobuf => github.com/gogo/protobuf v1.3.0
	github.com/gogo/protobuf v0.0.0-20190410021324-65acae22fc9 => github.com/gogo/protobuf v1.2.2-0.20190723190241-65acae22fc9d
	github.com/hashicorp/consul => github.com/hashicorp/consul v1.5.1
)

go 1.13
