package cmd

import (
	"github.com/ProtocolONE/auth1.protocol.one/pkg/api"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/config"
	"github.com/ProtocolONE/auth1.protocol.one/pkg/database"
	_ "github.com/ProtocolONE/auth1.protocol.one/pkg/database/migrations"
	"github.com/ProtocolONE/mfa-service/pkg"
	"github.com/ProtocolONE/mfa-service/pkg/proto"
	"github.com/boj/redistore"
	"github.com/globalsign/mgo"
	"github.com/go-redis/redis"
	"github.com/micro/go-micro"
	k8s "github.com/micro/kubernetes/go/micro"
	"github.com/ory/hydra/sdk/go/hydra"
	"github.com/spf13/cobra"
	migrate "github.com/xakep666/mongo-migrate"
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

	var service micro.Service
	if cfg.KubernetesHost == "" {
		service = micro.NewService()
		zap.L().Info("Initialize micro service")
	} else {
		service = k8s.NewService()
		zap.L().Info("Initialize k8s service")
	}
	service.Init()
	ms := proto.NewMfaService(mfa.ServiceName, service.Client())

	h, err := hydra.NewSDK(&hydra.Configuration{AdminURL: cfg.Hydra.AdminURL})
	if err != nil {
		zap.L().Fatal("Hydra SDK creation failed", zap.Error(err))
	}

	serverConfig := api.ServerConfig{
		ApiConfig:      &cfg.Server,
		DatabaseConfig: &cfg.Database,
		HydraConfig:    &cfg.Hydra,
		SessionConfig:  &cfg.Session,
		MfaService:     ms,
		Hydra:          h,
		ConnectionPool: db,
		SessionStore:   store,
		RedisClient:    redisClient,
	}
	server, err := api.NewServer(&serverConfig)
	if err != nil {
		zap.L().Fatal("Failed to create server", zap.Error(err))
	}

	zap.L().Info("Starting up server")
	if err = server.Start(); err != nil {
		zap.L().Fatal("Error running server", zap.Error(err))
	}
}

func createDatabase(cfg *config.Database) *database.ConnectionPool {
	db, err := database.NewConnection(cfg)
	if err != nil {
		zap.L().Fatal("Name connection failed with error", zap.Error(err))
	}

	if err := migrateDb(db, cfg.Name); err != nil {
		zap.L().Fatal("Error in db migration", zap.Error(err))
	}

	return database.NewConnectionPool(db, cfg.MaxConnections)
}

func migrateDb(s *mgo.Session, dbName string) error {
	db := s.DB(dbName)
	migrate.SetDatabase(db)

	if err := migrate.Up(migrate.AllAvailable); err != nil {
		if err := migrate.Down(migrate.AllAvailable); err != nil {
			return err
		}
	}

	return nil
}
