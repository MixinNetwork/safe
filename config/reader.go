package config

import (
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/MixinNetwork/safe/keeper"
	"github.com/MixinNetwork/safe/observer"
	"github.com/MixinNetwork/safe/signer"
	"github.com/pelletier/go-toml"
)

type Configuration struct {
	Signer   *signer.Configuration   `toml:"signer"`
	Keeper   *keeper.Configuration   `toml:"keeper"`
	Observer *observer.Configuration `toml:"observer"`
	Dev      *DevConfig              `toml:"observer"`
}

func ReadConfiguration(path string) (*Configuration, error) {
	if strings.HasPrefix(path, "~/") {
		usr, _ := user.Current()
		path = filepath.Join(usr.HomeDir, (path)[2:])
	}
	f, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var conf Configuration
	err = toml.Unmarshal(f, &conf)
	return &conf, err
}
