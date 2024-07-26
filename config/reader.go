package config

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"slices"
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
	Dev      *DevConfig              `toml:"dev"`
}

func ReadConfiguration(path, role string) (*Configuration, error) {
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
	if err != nil {
		return nil, err
	}
	handleDevConfig(conf.Dev)
	conf.checkMainnet(role)
	return &conf, nil
}

func (c *Configuration) checkMainnet(role string) {
	switch role {
	case "signer":
	case "keeper":
	case "observer":
	default:
		panic(role)
	}
	if c.Dev != nil && c.Dev.Network != MainNetworkName {
		return
	}

	s := c.Signer
	if role == "signer" {
		assert(s.AppId, SignerAppId, "signer.app-id")
		assert(s.KeeperAppId, KeeperAppId, "signer.keeper-app-id")
		assert(s.AssetId, SignerToken, "signer.asset-id")
		assert(s.KeeperAssetId, KeeperToken, "signer.keeper-asset-id")
	}
	if role == "signer" || role == "keeper" {
		assert(s.MTG.Genesis.Epoch, uint64(15903300), "signer.genesis.epoch")
		assert(s.MTG.Genesis.Threshold, int(19), "signer.genesis.threshold")
		if !slices.Equal(s.MTG.Genesis.Members, signers) {
			panic("signers")
		}
	}

	k := c.Keeper
	if role == "keeper" {
		assert(k.AppId, KeeperAppId, "keeper.app-id")
		assert(k.SignerAppId, SignerAppId, "keeper.signer-app-id")
		assert(k.AssetId, KeeperToken, "keeper.asset-id")
		assert(k.ObserverAssetId, ObserverToken, "keeper.observer-asset-id")
		assert(k.PolygonFactoryAddress, "0x4D17777E0AC12C6a0d4DEF1204278cFEAe142a1E", "keeper.polygon-factory-address")
		assert(k.PolygonObserverDepositEntry, "0x4A2eea63775F0407E1f0d147571a46959479dE12", "keeper.polygon-observer-deposit-entry")
		assert(k.PolygonKeeperDepositEntry, "0x5A3A6E35038f33458c13F3b5349ee5Ae1e94a8d9", "keeper.polygon-keeper-deposity-entry")
	}
	if role == "keeper" || role == "observer" {
		assert(k.MTG.Genesis.Epoch, uint64(15903300), "keeper.genesis.epoch")
		assert(k.MTG.Genesis.Threshold, int(19), "keeper.genesis.threshold")
		if !slices.Equal(k.MTG.Genesis.Members, keepers) {
			panic("keepers")
		}
	}

	if role == "observer" {
		o := c.Observer
		assert(o.KeeperAppId, KeeperAppId, "observer.keeper-app-id")
		assert(o.Timestamp, uint64(1721930640000000000), "observer.timestamp")
		assert(o.AssetId, ObserverToken, "observer.asset-id")
		assert(o.PolygonFactoryAddress, "0x4D17777E0AC12C6a0d4DEF1204278cFEAe142a1E", "observer.polygon-factory-address")
		assert(o.PolygonObserverDepositEntry, "0x4A2eea63775F0407E1f0d147571a46959479dE12", "observer.polygon-observer-deposit-entry")
		assert(o.PolygonKeeperDepositEntry, "0x5A3A6E35038f33458c13F3b5349ee5Ae1e94a8d9", "observer.polygon-keeper-deposity-entry")
	}
}

const (
	SignerAppId   = "bdee2414-045b-31b7-b8a7-7998b36f5c93"
	KeeperAppId   = "ac495e24-72a5-3c53-aa33-8f90cf007b9d"
	SignerToken   = "a946936b-1b52-3e02-aec6-4fbccf284d5f"
	KeeperToken   = "8205ed7b-d108-30c6-9121-e4b83eecef09"
	ObserverToken = "90f4351b-29b6-3b47-8b41-7efcec3c6672"
)

var (
	signers = []string{
		"a4930d3e-4783-4ccd-ae3e-f6651b5583c7",
		"2cf5645b-5c52-42e4-8c67-ed5164cfe8eb",
		"335654a7-986d-4600-ab89-b624e9998f36",
		"3d963e3c-2dd3-4902-b340-e8394d62ad0f",
		"ed3d5824-87e4-4060-b347-90b3a3aa16fb",
		"a8327607-724d-45d4-afca-339d33219d1a",
		"9ad6076e-c79d-4571-b29a-4671262c2538",
		"b1081493-d702-43e1-8051-cec283e9898f",
		"f5a9bf39-2e3d-49d9-bbfc-144aaf209157",
		"bfe8c7b9-58a3-4d2d-92b4-ba5b67eb1a42",
		"da9bdc94-a446-422c-ab90-8ab9c5bb8bc7",
		"9fcdea14-03d1-49f1-af97-4079c9551777",
		"8cf9b500-0bc8-408e-890b-41873e162345",
		"72b336e4-1e05-477a-8254-2f02a6249ffd",
		"5ae7f5cf-26b8-4ea6-b031-2bf3af09da57",
		"18f2c8ad-ac9b-4a6f-a074-240bfacbe58b",
		"21da6e56-f335-45c4-a838-9a0139fe7269",
		"83170828-5bd8-491d-9bb0-f1af072c305b",
		"40032eda-126b-44f2-bfb9-76da965cf0c2",
		"fb264547-198d-4877-9ef9-66f6b3f4e3d7",
		"a3a68c12-2407-4c3b-ad5d-5c37a3d29b1a",
		"77a3a6fe-fc4c-4035-8409-0f4b5daba51d",
		"1e3c4323-207d-4d7b-bcd6-21b35d02bdb7",
		"fca01bd7-3e87-4d9e-bf88-cbd8f642cc16",
		"7552beb9-4a7b-4cbb-a026-f4db1d86cbf9",
		"575ede5a-4802-42e8-81b1-6b2e2ef187d8",
		"07775ff6-bb41-4fbd-9f81-8e600898ee6e",
	}
	keepers = append(signers, "c91eb626-eb89-4fbd-ae21-76f0bd763da5")
)

func assert(a, b any, name string) {
	if a != b {
		panic(fmt.Sprintf("%s %v != %v", name, a, b))
	}
}
