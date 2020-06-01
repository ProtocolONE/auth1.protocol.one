package grpc

import (
	"net"

	"github.com/ProtocolONE/auth1.protocol.one/internal/grpc/handler"
	"github.com/ProtocolONE/auth1.protocol.one/internal/grpc/proto"
	"go.uber.org/fx"
	"google.golang.org/grpc"
)

type Server struct {
	*grpc.Server
	listener *net.Listener
}

type Params struct {
	fx.In

	Service *handler.Handler
}

func NewServer(p Params) (*Server, error) {
	listener, err := net.Listen("tcp", ":5300")
	if err != nil {
		return nil, err
	}

	server := grpc.NewServer()
	proto.RegisterServiceServer(server, p.Service)

	return &Server{
		Server:   server,
		listener: &listener,
	}, nil
}

func (s *Server) Run() error {
	return s.Serve(*s.listener)
}
