package config

import (
	"crypto/rsa"
	"strings"

	"github.com/spf13/viper"
)

type (
	ApiConfig struct {
		Port         int
		Debug        bool
		TimeoutRead  int
		TimeoutWrite int
	}

	JwtConfig struct {
		SignatureSecret       *rsa.PublicKey
		SignatureSecretBase64 string
		Algorithm             string
	}

	DatabaseConfig struct {
		Host     string
		Database string
		User     string
		Password string
	}

	RedisConfig struct {
		Addr     string
		Password string
	}

	Config struct {
		Api      ApiConfig
		Jwt      JwtConfig
		Logger   LoggingConfig
		Database DatabaseConfig
		Redis    RedisConfig
	}
)

func LoadConfig(configFile string) (*Config, error) {
	viper.SetEnvPrefix("AUTHONE")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()

	if configFile != "" {
		viper.SetConfigFile(configFile)
	} else {
		viper.SetConfigName("config")
		viper.AddConfigPath("./")
		viper.AddConfigPath("$HOME/config.example")
	}

	if err := viper.ReadInConfig(); err != nil {
		return nil, err
	}

	config := new(Config)
	if err := viper.Unmarshal(config); err != nil {
		return nil, err
	}

	return config, nil
}
