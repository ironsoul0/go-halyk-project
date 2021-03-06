package util

import (
	"github.com/spf13/viper"
)

type Config struct {
	DBSource            string `mapstructure:"DB_SOURCE"`
	AccessSecret        string `mapstructure:"ACCESS_SECRET"`
	RefreshSecret       string `mapstructure:"REFRESH_SECRET"`
	RedisAddress        string `mapstructure:"REDIS_ADDRESS"`
	Port                string `mapstructure:"PORT"`
	TransactionsService string `mapstructure:"TRANSACTIONS_SERVICE"`
	Origin              string `mapstructure:"ORIGIN"`
}

func LoadConfig(path string) (config Config, err error) {
	viper.AddConfigPath(path)
	viper.SetConfigName("app")
	viper.SetConfigType("env")

	viper.AutomaticEnv()

	err = viper.ReadInConfig()
	if err != nil {
		return
	}

	err = viper.Unmarshal(&config)
	return
}
