package main

import (
	"github.com/ProtocolONE/auth1.protocol.one/cmd"
	_ "net/http/pprof"
)

func main() {
	cmd.Execute()
}
