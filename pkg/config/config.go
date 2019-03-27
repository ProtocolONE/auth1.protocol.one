package config

import (
	"crypto/rsa"
	"strings"

	"github.com/spf13/viper"
)

type (
	ApiConfig struct {
		Port             int
		Debug            bool
		TimeoutRead      int
		TimeoutWrite     int
		AllowOrigins     []string
		AllowCredentials bool
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

	HydraConfig struct {
		PublicURL string
		AdminURL  string
	}

	KubernetesConfig struct {
		Service KubernetesServiceConfig
	}

	KubernetesServiceConfig struct {
		Host string
	}

	SessionConfig struct {
		Size     int
		Network  string
		Secret   string
		Name     string
		Address  string
		Password string
	}

	Config struct {
		Api        ApiConfig
		Jwt        JwtConfig
		Database   DatabaseConfig
		Redis      RedisConfig
		Kubernetes KubernetesConfig
		Hydra      HydraConfig
		Session    SessionConfig
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
