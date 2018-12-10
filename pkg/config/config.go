package config

import (
	"crypto/rsa"
	"strings"

	"github.com/spf13/viper"
)

type (
	ServerConfig struct {
		Port         int
		Debug        bool
		TimeoutRead  int
		TimeoutWrite int
	}

	Jwt struct {
		SignatureSecret       *rsa.PublicKey
		SignatureSecretBase64 string
		Algorithm             string
	}

	Config struct {
		Server    ServerConfig
		Jwt       Jwt
		LogConfig LoggingConfig
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
