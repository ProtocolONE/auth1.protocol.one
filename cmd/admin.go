package cmd

import (
	"github.com/ProtocolONE/auth1.protocol.one/internal/admin"
	"github.com/spf13/cobra"
)

var adminCmd = &cobra.Command{
	Use:   "admin",
	Short: "Start AuthOne administration server",
	RunE:  runAdminServer,
}

func runAdminServer(cmd *cobra.Command, args []string) error {
	s := admin.NewServer()

	return s.Serve(":8080")
}
