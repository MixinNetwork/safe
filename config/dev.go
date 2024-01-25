package config

import (
	"net/http"
	_ "net/http/pprof"

	"github.com/MixinNetwork/mixin/logger"
)

type DevConfig struct {
	EnableProfile bool `toml:"enable-profile"`
	LogLevel      int  `toml:"log-level"`
}

func HandleDevConfig(c *DevConfig) {
	logger.SetLevel(c.LogLevel)
	if c.EnableProfile {
		go http.ListenAndServe("127.0.0.1:12345", http.DefaultServeMux)
	}
}
