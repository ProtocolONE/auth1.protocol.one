package cmd

import (
	"github.com/ProtocolONE/auth1.protocol.one/pkg/config"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/database"
	_ "github.com/ProtocolONE/auth1.protocol.one/pkg/database/migrations"
	"github.com/spf13/cobra"
	"github.com/xakep666/mongo-migrate"
	"go.uber.org/zap"
)

var migrationCmd = &cobra.Command{
	Use:   "migration",
	Short: "Run AuthOne migration",
	Run:   runMigration,
}

func runMigration(cmd *cobra.Command, args []string) {
	err := config.Load(&cfg)
	if err != nil {
		logger.Fatal("Failed to load config", zap.Error(err))
	}

	db, err := database.NewConnection(&cfg.Database)
	if err != nil {
		zap.L().Fatal("DB connection failed with error", zap.Error(err))
	}
	defer db.Close()

	if cfg.MigrationDirect != "" {
		if err := migrateDb(db, cfg.MigrationDirect); err != nil {
			zap.L().Fatal("Error in db migration", zap.Error(err))
		}
	}

	return
}

func migrateDb(s database.MgoSession, direction string) error {
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
