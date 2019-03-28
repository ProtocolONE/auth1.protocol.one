package main

import (
	"github.com/ProtocolONE/auth1.protocol.one/cmd"
	"log"
	"net/http"
	_ "net/http/pprof"
)

func main() {
	go func() {
		log.Println(http.ListenAndServe("localhost:6060", nil))
	}()

	cmd.Execute()
}
