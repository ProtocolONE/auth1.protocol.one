package cmd

import (
	"github.com/ProtocolONE/auth1.protocol.one/pkg/database"
	_ "github.com/ProtocolONE/auth1.protocol.one/pkg/database/migrations"
	"github.com/globalsign/mgo"
	"github.com/spf13/cobra"
	"github.com/xakep666/mongo-migrate"
	"go.uber.org/zap"
)

var migrationCmd = &cobra.Command{
	Use:   "migration",
	Short: "Run AuthOne migration",
	Run:   runMigration,
}

func init() {
	command.AddCommand(migrationCmd)
}

func runMigration(cmd *cobra.Command, args []string) {
	db, err := database.NewConnection(&cfg.Database)
	if err != nil {
		zap.L().Fatal("Name connection failed with error", zap.Error(err))
	}
	defer db.Close()

	if cfg.MigrationDirect != "" {
		if err := migrateDb(db, cfg.MigrationDirect); err != nil {
			zap.L().Fatal("Error in db migration", zap.Error(err))
		}
	}

	return
}

func migrateDb(s *mgo.Session, direction string) error {
	migrate.SetDatabase(s.DB(""))
	migrate.SetMigrationsCollection("auth1-migration")

	if direction == "up" {
		if err := migrate.Up(migrate.AllAvailable); err != nil {
			return err
		}
	}

	if direction == "down" {
		if err := migrate.Down(migrate.AllAvailable); err != nil {
			return err
		}
	}

	return nil
}
