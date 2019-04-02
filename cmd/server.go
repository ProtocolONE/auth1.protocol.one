package cmd

import (
	"github.com/ProtocolONE/auth1.protocol.one/pkg/api"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/config"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/database"
	"github.com/boj/redistore"
	"github.com/globalsign/mgo"
	"github.com/go-redis/redis"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Run AuthOne api server with given configuration",
	Run:   runServer,
}

func init() {
	command.AddCommand(serverCmd)
}

func runServer(cmd *cobra.Command, args []string) {
	store, err := redistore.NewRediStore(
		cfg.Session.Size,
		cfg.Session.Network,
		cfg.Session.Address,
		cfg.Session.Password,
		[]byte(cfg.Session.Secret),
	)
	if err != nil {
		zap.L().Fatal("Unable to start redis session store", zap.Error(err))
	}
	defer store.Close()

	db := createDatabase(&cfg.Database)
	defer db.Close()

	redisClient := redis.NewClient(&redis.Options{
		Addr:     cfg.Redis.Addr,
		Password: cfg.Redis.Password,
	})
	defer redisClient.Close()

	serverConfig := api.ServerConfig{
		JwtConfig:      &cfg.Jwt,
		ApiConfig:      &cfg.Api,
		DatabaseConfig: &cfg.Database,
		Kubernetes:     &cfg.Kubernetes,
		HydraConfig:    &cfg.Hydra,
		SessionConfig:  &cfg.Session,
		MongoDB:        db,
		SessionStore:   store,
		RedisClient:    redisClient,
	}
	server, err := api.NewServer(&serverConfig)
	if err != nil {
		zap.L().Fatal("Failed to create server", zap.Error(err))
	}

	zap.L().Info("Starting up server")

	err = server.Start()
	if err != nil {
		zap.L().Fatal("Failed to start server", zap.Error(err))
	}
}

func createDatabase(cfg *config.DatabaseConfig) *mgo.Session {
	db, err := database.NewConnection(cfg)
	if err != nil {
		zap.L().Fatal("Database connection failed with error", zap.Error(err))
	}

	if err := database.MigrateDb(db, cfg.Database); err != nil {
		zap.L().Fatal("Error in db migration", zap.Error(err))
	}
	return db
}
