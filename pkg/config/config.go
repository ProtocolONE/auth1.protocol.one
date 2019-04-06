package config

import (
	"github.com/kelseyhightower/envconfig"
)

type Config struct {
	Server   Server
	Database Database
	Redis    Redis
	Hydra    Hydra
	Session  Session

	KubernetesHost  string `envconfig:"KUBERNETES_SERVICE_HOST" required:"false"`
	MigrationDirect string `envconfig:"MIGRATION_DIRECT" required:"false"`
}

type Server struct {
	Port             int      `envconfig:"PORT" required:"false" default:"8080"`
	Debug            bool     `envconfig:"DEBUG" required:"false" default:"true"`
	TimeoutRead      int      `envconfig:"TIMEOUT_READ" required:"false" default:"15"`
	TimeoutWrite     int      `envconfig:"TIMEOUT_WRITE" required:"false" default:"5"`
	AllowOrigins     []string `envconfig:"ALLOW_ORIGINS" required:"false" default:"*"`
	AllowCredentials bool     `envconfig:"ALLOW_CREDENTIALS" required:"false" default:"true"`
}

type Database struct {
	Host           string `envconfig:"HOST" required:"false" default:"127.0.0.1"`
	Name           string `envconfig:"DATABASE" required:"false" default:"auth-one"`
	User           string `envconfig:"USER" required:"false"`
	Password       string `envconfig:"PASSWORD" required:"false"`
	MaxConnections int    `envconfig:"MAX_CONNECTIONS" required:"false" default:"100"`
}

type Redis struct {
	Addr     string `envconfig:"ADDRESS" required:"false" default:"127.0.0.1:6379"`
	Password string `envconfig:"PASSWORD" required:"false" default:""`
}

type Hydra struct {
	PublicURL string `envconfig:"PUBLIC_URL" required:"false" default:"http://localhost:4444"`
	AdminURL  string `envconfig:"ADMIN_URL" required:"false" default:"http://localhost:4445"`
}

type Session struct {
	Size     int    `envconfig:"SIZE" required:"false" default:"1"`
	Network  string `envconfig:"NETWORK" required:"false" default:"tcp"`
	Secret   string `envconfig:"SECRET" required:"false" default:"secretkey"`
	Name     string `envconfig:"NAME" required:"false" default:"sessid"`
	Address  string `envconfig:"ADDRESS" required:"false" default:"127.0.0.1:6379"`
	Password string `envconfig:"PASSWORD" required:"false" default:""`
}

func Load() (*Config, error) {
	config := &Config{}
	return config, envconfig.Process("AUTHONE", config)
}
