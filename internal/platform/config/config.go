package config

import (
	"os"
	"strconv"
)

type Config struct {
	DB_DSN      string
	BcryptCost  int
	Addr        string
}

func Load() Config {
	cost := 12
	if v := os.Getenv("BCRYPT_COST"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil {
			cost = parsed
		}
	}
	
	addr := os.Getenv("APP_ADDR")
	if addr == "" {
		addr = ":8084"  // используем порт 8084 чтобы не конфликтовать с другими проектами
	}

	return Config{
		DB_DSN:     os.Getenv("DB_DSN"),
		BcryptCost: cost,
		Addr:       addr,
	}
}
