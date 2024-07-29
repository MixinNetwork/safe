package config

import (
	"fmt"
	"net/http"
	_ "net/http/pprof"

	"github.com/MixinNetwork/mixin/logger"
)

const MainNetworkName = "main"
const TestNetworkName = "test"

type DevConfig struct {
	ProfilePort int    `toml:"profile-port"`
	LogLevel    int    `toml:"log-level"`
	Network     string `toml:"network"`
}

func handleDevConfig(c *DevConfig) {
	logger.SetLevel(logger.INFO)
	if c == nil {
		return
	}
	logger.SetLevel(c.LogLevel)
	if c.ProfilePort > 1000 {
		l := fmt.Sprintf("127.0.0.1:%d", c.ProfilePort)
		go http.ListenAndServe(l, http.DefaultServeMux)
	}
	if c.Network == "" {
		c.Network = MainNetworkName
	}
}
