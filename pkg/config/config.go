package config

import (
	"github.com/kelseyhightower/envconfig"
)

// Config is general configuration settings for the application.
type Config struct {
	// Server contains settings for http application.
	Server Server

	// Database contains settings for connection to the database.
	Database Database

	// Redis contains settings for connection to the Redis.
	Redis Redis

	// Hydra contains settings for public and private urls of the Hydra api.
	Hydra Hydra

	// Session contains settings for the session.
	Session Session

	// Mailer contains settings for the postman service.
	Mailer Mailer

	// Recaptcha contains settings for recaptcha integration.
	Recaptcha Recaptcha

	// MigrationDirect specifies direction for database migrations.
	MigrationDirect string `envconfig:"MIGRATION_DIRECT" required:"false"`
}

// Server contains settings for http application.
type Server struct {
	Port              int      `envconfig:"PORT" required:"false" default:"8080"`
	Debug             bool     `envconfig:"DEBUG" required:"false" default:"true"`
	AllowOrigins      []string `envconfig:"ALLOW_ORIGINS" required:"false" default:"*"`
	AllowCredentials  bool     `envconfig:"ALLOW_CREDENTIALS" required:"false" default:"true"`
	AuthWebFormSdkUrl string   `envconfig:"AUTH_WEB_FORM_SDK_URL" required:"false" default:"https://static.protocol.one/auth/form/dev/auth-web-form.js"`
}

// Database contains settings for connection to the database.
type Database struct {
	Host           string `envconfig:"HOST" required:"false" default:"127.0.0.1"`
	Name           string `envconfig:"DATABASE" required:"false" default:"auth-one"`
	User           string `envconfig:"USER" required:"false"`
	Password       string `envconfig:"PASSWORD" required:"false"`
	MaxConnections int    `envconfig:"MAX_CONNECTIONS" required:"false" default:"100"`
	Dsn            string `envconfig:"DSN" required:"false" default:""`
}

// Redis contains settings for connection to the Redis.
type Redis struct {
	Addr     string `envconfig:"ADDRESS" required:"false" default:"127.0.0.1:6379"`
	Password string `envconfig:"PASSWORD" required:"false" default:""`
}

// Hydra contains settings for public and private urls of the Hydra api.
type Hydra struct {
	PublicURL string `envconfig:"PUBLIC_URL" required:"false" default:"http://localhost:4444"`
	AdminURL  string `envconfig:"ADMIN_URL" required:"false" default:"http://localhost:4445"`
}

// Session contains settings for the session.
type Session struct {
	Size     int    `envconfig:"SIZE" required:"false" default:"1"`
	Network  string `envconfig:"NETWORK" required:"false" default:"tcp"`
	Secret   string `envconfig:"SECRET" required:"false" default:"secretkey"`
	Name     string `envconfig:"NAME" required:"false" default:"sessid"`
	Address  string `envconfig:"ADDRESS" required:"false" default:"127.0.0.1:6379"`
	Password string `envconfig:"PASSWORD" required:"false" default:""`
}

// Mailer specifies all the parameters needed for dump mail sender
type Mailer struct {
	Host               string `envconfig:"HOST" required:"false" default:"localhost"`
	Port               int    `envconfig:"PORT" required:"false" default:"25"`
	Username           string `envconfig:"USERNAME" required:"false" default:""`
	Password           string `envconfig:"PASSWORD" required:"false" default:""`
	ReplyTo            string `envconfig:"REPLY_TO" required:"false" default:""`
	From               string `envconfig:"FROM" required:"false" default:""`
	InsecureSkipVerify bool   `envconfig:"SKIP_VERIFY" required:"false" default:"true"`
}

type Recaptcha struct {
	Key      string `envconfig:"KEY" required:"false" default:""`
	Secret   string `envconfig:"SECRET" required:"false" default:""`
	Hostname string `envconfig:"HOSTNAME" required:"false" default:""`
}

func Load() (*Config, error) {
	config := &Config{}
	return config, envconfig.Process("AUTHONE", config)
}
