package observer

import (
	"fmt"
	"strings"
	"testing"

	"github.com/MixinNetwork/safe/apps/ethereum"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/common/abi"
	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/require"
)

// type DepositEntry struct {
// 	Destination string
// 	Tag         string
// }

// type SafeDepositView struct {
// 	DepositHash  string `json:"deposit_hash"`
// 	DepositIndex int64  `json:"deposit_index"`
// 	Sender       string `json:"sender"`
// 	Destination  string `json:"destination"`
// 	Tag          string `json:"tag"`
// }

// func (e DepositEntry) UniqueKey() string {
// 	return fmt.Sprintf("%s:%s", e.Destination, e.Tag)
// }

// func readOutputDepositUntilSufficient(ctx context.Context, id string) (*SafeDepositView, error) {
// 	for {
// 		var deposit *SafeDepositView
// 		err := grp.mixin.Get(ctx, fmt.Sprintf("/safe/outputs/%s/deposit", id), nil, &deposit)
// 		logger.Verbosef("Group.readOutputDeposit(%s) => %v %v\n", id, deposit, err)
// 		if err != nil {
// 			if mtg.CheckRetryableError(err) {
// 				time.Sleep(3 * time.Second)
// 				continue
// 			}
// 			if strings.Contains(err.Error(), "not found") {
// 				return nil, nil
// 			}
// 		}
// 		return deposit, err
// 	}
// }

func TestAsset(t *testing.T) {
	require := require.New(t)

	storageTraceId := uuid.FromStringOrNil("")
	fmt.Println(storageTraceId)
	return

	abi.InitFactoryContractAddress("0x39490616B61302B7d0Af8993cB694a54064EBA17")
	// abi.InitFactoryContractAddress("0x4D17777E0AC12C6a0d4DEF1204278cFEAe142a1E")

	entry := "0x11EC02748116A983deeD59235302C3139D6e8cdD" // keeper
	// entry := "0x9d04735aaEB73535672200950fA77C2dFC86eB21" // observer
	holder := "020b44b15ca73d0c0ab55c01e6b7ad5fda49b17cea6849fd33ff62fead193f6cb8"

	assetId := "76c802a2-7c88-447f-a93e-c29c9e5dd9c8"
	symbol := "LTC"
	name := "Litecoin"

	addr := abi.GetFactoryAssetAddress(entry, assetId, symbol, name, holder)
	assetKey := strings.ToLower(addr.String())
	err := ethereum.VerifyAssetKey(assetKey)
	require.Nil(err)
	safeAssetId := ethereum.GenerateAssetId(common.SafeChainPolygon, assetKey)
	fmt.Println(safeAssetId)
}
