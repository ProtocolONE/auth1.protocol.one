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

	KubernetesConfig struct {
		Service KubernetesServiceConfig
	}

	KubernetesServiceConfig struct {
		Host string
	}

	Config struct {
		Api        ApiConfig
		Jwt        JwtConfig
		Database   DatabaseConfig
		Redis      RedisConfig
		Kubernetes KubernetesConfig
	}
)

func LoadConfig(configFile string) (*Config, error) {
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()

	if configFile != "" {
		viper.SetConfigFile(configFile)
	} else {
		viper.SetConfigName("config")
		viper.AddConfigPath("./")
		viper.AddConfigPath("$HOME")
		viper.AddConfigPath("./etc")
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
