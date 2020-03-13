package main

import (
	_ "net/http/pprof"

	"github.com/ProtocolONE/auth1.protocol.one/cmd"
)

func main() {
	cmd.Execute()
}
