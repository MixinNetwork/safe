package config

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/MixinNetwork/safe/keeper"
	"github.com/MixinNetwork/safe/mtg"
	"github.com/MixinNetwork/safe/observer"
	"github.com/MixinNetwork/safe/signer"
	"github.com/pelletier/go-toml"
	"github.com/stretchr/testify/require"
)

func TestNetworkConfigurationChecksAllRoles(t *testing.T) {
	for _, network := range []string{MainNetworkName, TestNetworkName} {
		for _, role := range []string{"signer", "keeper", "observer"} {
			configuration := coverageConfiguration(network)
			configuration.checkMainnet(role)
			configuration.checkTestnet(role)
		}
	}

	mainWithoutDev := coverageConfiguration(MainNetworkName)
	mainWithoutDev.Dev = nil
	mainWithoutDev.checkMainnet("signer")

	custom := coverageConfiguration(MainNetworkName)
	custom.Dev.Network = "custom"
	custom.checkMainnet("signer")
	custom.checkTestnet("signer")

	require.Panics(t, func() { coverageConfiguration(MainNetworkName).checkMainnet("invalid") })
	require.Panics(t, func() { coverageConfiguration(TestNetworkName).checkTestnet("invalid") })
}

func TestNetworkConfigurationRejectsChangedProductionValues(t *testing.T) {
	mainSigner := coverageConfiguration(MainNetworkName)
	mainSigner.Signer.AppId = "changed"
	require.Panics(t, func() { mainSigner.checkMainnet("signer") })

	mainMembers := coverageConfiguration(MainNetworkName)
	mainMembers.Signer.MTG.Genesis.Members[0] = "changed"
	require.Panics(t, func() { mainMembers.checkMainnet("keeper") })

	mainKeepers := coverageConfiguration(MainNetworkName)
	mainKeepers.Keeper.MTG.Genesis.Members[0] = "changed"
	require.Panics(t, func() { mainKeepers.checkMainnet("observer") })

	testSigner := coverageConfiguration(TestNetworkName)
	testSigner.Signer.MTG.Genesis.Members[0] = "changed"
	require.Panics(t, func() { testSigner.checkTestnet("signer") })

	testKeepers := coverageConfiguration(TestNetworkName)
	testKeepers.Keeper.MTG.Genesis.Members[0] = "changed"
	require.Panics(t, func() { testKeepers.checkTestnet("observer") })
}

func TestReadConfigurationSuccessAndFailures(t *testing.T) {
	_, err := ReadConfiguration(filepath.Join(t.TempDir(), "missing.toml"), "signer")
	require.Error(t, err)
	_, err = ReadConfiguration("~/safe-coverage-definitely-missing.toml", "signer")
	require.Error(t, err)

	invalidPath := filepath.Join(t.TempDir(), "invalid.toml")
	require.NoError(t, os.WriteFile(invalidPath, []byte("invalid = ["), 0o600))
	_, err = ReadConfiguration(invalidPath, "signer")
	require.Error(t, err)

	want := coverageConfiguration(TestNetworkName)
	raw, err := toml.Marshal(want)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "valid.toml")
	require.NoError(t, os.WriteFile(path, raw, 0o600))
	got, err := ReadConfiguration(path, "signer")
	require.NoError(t, err)
	require.True(t, slices.IsSorted(got.Signer.MTG.Genesis.Members))
	require.True(t, slices.IsSorted(got.Keeper.MTG.Genesis.Members))
	require.Equal(t, TestNetworkName, got.Dev.Network)
}

func TestHandleDevConfigurationDefaults(t *testing.T) {
	handleDevConfig(nil)

	configuration := &DevConfig{LogLevel: 1}
	handleDevConfig(configuration)
	require.Equal(t, MainNetworkName, configuration.Network)

	configuration = &DevConfig{LogLevel: 2, Network: TestNetworkName, ProfilePort: 70_000}
	handleDevConfig(configuration)
	require.Equal(t, TestNetworkName, configuration.Network)
}

func coverageConfiguration(network string) *Configuration {
	signerMembers := coverageSignerMembers(network)
	keeperMembers := append(slices.Clone(signerMembers), coverageKeeperMember(network))

	signerConfiguration := &signer.Configuration{MTG: &mtg.Configuration{}}
	keeperConfiguration := &keeper.Configuration{MTG: &mtg.Configuration{}}
	observerConfiguration := &observer.Configuration{}
	configuration := &Configuration{
		Signer:   signerConfiguration,
		Keeper:   keeperConfiguration,
		Observer: observerConfiguration,
		Dev:      &DevConfig{Network: network},
	}

	if network == MainNetworkName {
		signerConfiguration.AppId = "bdee2414-045b-31b7-b8a7-7998b36f5c93"
		signerConfiguration.KeeperAppId = "ac495e24-72a5-3c53-aa33-8f90cf007b9d"
		signerConfiguration.AssetId = "a946936b-1b52-3e02-aec6-4fbccf284d5f"
		signerConfiguration.KeeperAssetId = "8205ed7b-d108-30c6-9121-e4b83eecef09"
		signerConfiguration.MTG.Genesis.Epoch = 15_903_300
		signerConfiguration.MTG.Genesis.Threshold = 19

		keeperConfiguration.AppId = "ac495e24-72a5-3c53-aa33-8f90cf007b9d"
		keeperConfiguration.SignerAppId = "bdee2414-045b-31b7-b8a7-7998b36f5c93"
		keeperConfiguration.AssetId = "8205ed7b-d108-30c6-9121-e4b83eecef09"
		keeperConfiguration.ObserverAssetId = "90f4351b-29b6-3b47-8b41-7efcec3c6672"
		keeperConfiguration.PolygonFactoryAddress = "0x4D17777E0AC12C6a0d4DEF1204278cFEAe142a1E"
		keeperConfiguration.PolygonObserverDepositEntry = "0x4A2eea63775F0407E1f0d147571a46959479dE12"
		keeperConfiguration.PolygonKeeperDepositEntry = "0x5A3A6E35038f33458c13F3b5349ee5Ae1e94a8d9"
		keeperConfiguration.MTG.Genesis.Epoch = 15_903_300
		keeperConfiguration.MTG.Genesis.Threshold = 19

		observerConfiguration.KeeperAppId = keeperConfiguration.AppId
		observerConfiguration.Timestamp = 1_721_930_640_000_000_000
		observerConfiguration.AssetId = keeperConfiguration.ObserverAssetId
		observerConfiguration.PolygonFactoryAddress = keeperConfiguration.PolygonFactoryAddress
		observerConfiguration.PolygonObserverDepositEntry = keeperConfiguration.PolygonObserverDepositEntry
		observerConfiguration.PolygonKeeperDepositEntry = keeperConfiguration.PolygonKeeperDepositEntry
	} else {
		signerConfiguration.AppId = "01fff6be-5ace-30d1-89b1-00af0a20fe6b"
		signerConfiguration.KeeperAppId = "7a1a7f4b-4ff3-3e2a-ae10-e6b81c066ba1"
		signerConfiguration.AssetId = "153a900b-ed21-376a-8419-7582840a308c"
		signerConfiguration.KeeperAssetId = "edcf2f60-c256-3693-a1cc-9e75e87e23c5"
		signerConfiguration.MTG.Genesis.Epoch = 9_877_485
		signerConfiguration.MTG.Genesis.Threshold = 4

		keeperConfiguration.AppId = "7a1a7f4b-4ff3-3e2a-ae10-e6b81c066ba1"
		keeperConfiguration.SignerAppId = "01fff6be-5ace-30d1-89b1-00af0a20fe6b"
		keeperConfiguration.AssetId = "edcf2f60-c256-3693-a1cc-9e75e87e23c5"
		keeperConfiguration.ObserverAssetId = "5ee8ddb6-de43-33b8-a758-e32f908a3096"
		keeperConfiguration.PolygonFactoryAddress = "0x4D17777E0AC12C6a0d4DEF1204278cFEAe142a1E"
		keeperConfiguration.PolygonObserverDepositEntry = "0x9d04735aaEB73535672200950fA77C2dFC86eB21"
		keeperConfiguration.PolygonKeeperDepositEntry = "0x11EC02748116A983deeD59235302C3139D6e8cdD"
		keeperConfiguration.MTG.Genesis.Epoch = 9_877_485
		keeperConfiguration.MTG.Genesis.Threshold = 4

		observerConfiguration.KeeperAppId = keeperConfiguration.AppId
		observerConfiguration.Timestamp = 1_721_930_640_000_000_000
		observerConfiguration.AssetId = keeperConfiguration.ObserverAssetId
		observerConfiguration.PolygonFactoryAddress = keeperConfiguration.PolygonFactoryAddress
		observerConfiguration.PolygonObserverDepositEntry = keeperConfiguration.PolygonObserverDepositEntry
		observerConfiguration.PolygonKeeperDepositEntry = keeperConfiguration.PolygonKeeperDepositEntry
	}

	signerConfiguration.MTG.Genesis.Members = slices.Clone(signerMembers)
	keeperConfiguration.MTG.Genesis.Members = slices.Clone(keeperMembers)
	return configuration
}

func coverageKeeperMember(network string) string {
	if network == MainNetworkName {
		return "c91eb626-eb89-4fbd-ae21-76f0bd763da5"
	}
	return "fcb87491-4fa0-4c2f-b387-262b63cbc112"
}

func coverageSignerMembers(network string) []string {
	if network == TestNetworkName {
		return []string{
			"71b72e67-3636-473a-9ee4-db7ba3094057",
			"148e696f-f1db-4472-a907-ceea50c5cfde",
			"c9a9a719-4679-4057-bcf0-98945ed95a81",
			"b45dcee0-23d7-4ad1-b51e-c681a257c13e",
		}
	}
	return []string{
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
}
