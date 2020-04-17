package micro

import (
	"time"

	grpc2 "github.com/ProtocolONE/auth1.protocol.one/internal/handler/grpc"
	"github.com/ProtocolONE/auth1.protocol.one/internal/handler/proto"
	"github.com/micro/go-micro/v2/service"
	"github.com/micro/go-micro/v2/service/grpc"
	"go.uber.org/fx"
)

type Params struct {
	fx.In

	Handler *grpc2.Handler
}

func New(params Params) (service.Service, error) {
	s := grpc.NewService(
		service.Name("p1.auth1.grpc"),            // todo: rename
		service.Version("latest"),                // todo: take from variable
		service.RegisterTTL(time.Second*30),      // todo: load from config
		service.RegisterInterval(time.Second*10), // todo: load from config
		service.Address(":9081"),                 // todo: load from config
	)
	s.Init()
	err := proto.RegisterServiceHandler(s.Server(), params.Handler)
	if err != nil {
		return nil, err
	}
	return s, nil
}
