package keeper

import (
	"fmt"
	"math/big"
	"sort"
	"testing"

	"github.com/MixinNetwork/safe/common"
	"github.com/stretchr/testify/assert"
)

func TestKeygenOperationId(t *testing.T) {
	assert := assert.New(t)
	batch := big.NewInt(16)
	reqId := "11799833-f593-37ec-a826-991530fadcbd"
	genesis := "8521bafc4e91fc809218c27dafa990b7380d036e84f63bcf9f8cceb27cc2aa7b"
	signers := []string{
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
	sort.Strings(signers)
	threshold := 19
	oids := map[int]string{
		0:  "6bff51b2-773b-345b-997c-3b8ca7ae4bf3",
		1:  "4444983c-f60a-3e8f-89a1-6a764f458861",
		2:  "bf34e6fe-1eae-38d5-839b-cc98dcab3b9e",
		3:  "a22648c4-1c51-3f01-a5cc-d8b573d9c2f1",
		4:  "4026d2ba-4984-3574-96c2-b5eb02137b25",
		5:  "b6c29f05-2949-356d-a8eb-1a7fccd44326",
		6:  "3cf6f2e9-f6d8-3760-be81-40dc38848c58",
		7:  "4c6f8215-ad20-3a27-b6e4-9d8a3e092038",
		8:  "25ecf56f-1e12-3e4f-ab24-cff4aad74f74",
		9:  "be7194c9-b3b1-3a62-847d-297c7c621cc6",
		10: "5ab25bee-851e-3539-954c-5c9c53579c15",
		11: "656b7db0-7bdf-3274-b4a3-a2f59acc8c7e",
		12: "b330341a-4803-3184-ace4-456ba57ff744",
		13: "89deb131-7bfe-343f-9783-b3bf86da49b9",
		14: "e679c90b-fe54-3344-af3b-8c66eb73ccc4",
		15: "64a2a577-c8fc-3e01-9cc5-fccc3b51f60a",
	}
	tids := map[int]string{
		0:  "24a1cdf1-872d-3cc2-b826-e2a888b67303",
		1:  "b24d0431-f29a-3c0c-b0e8-652415a3b251",
		2:  "075fbe66-fcd2-34b5-bda7-0a57c056f33a",
		3:  "08b2234f-0260-39d8-ab37-d49c359326a4",
		4:  "9ca6c81f-053d-3131-aa0b-829c8e6c8daa",
		5:  "12e04a02-89d5-30d3-9faf-92d2874152f3",
		6:  "a8f4064d-aa7a-3f68-9987-453f344d3931",
		7:  "1661b59d-d85b-3197-8c94-b586bccffcd3",
		8:  "43a1ec47-5db2-3268-b9e2-f1010614f735",
		9:  "86e915af-6717-33d2-9549-c2d9759247ec",
		10: "c1cdd10b-e80b-35c5-8a00-3492ca19874c",
		11: "f78d4585-eff7-3bbc-b140-d59209475d03",
		12: "400da4fc-8766-36aa-9d40-3d6886d6e878",
		13: "e07beae0-4afa-32cb-9c51-f00639133d6c",
		14: "974ddd96-6903-3eb6-b1a4-6edb7915f8b5",
		15: "74b1aeff-e9e0-3abe-80cc-e9beb9199623",
	}
	aesKey := make([]byte, 32)
	for i := range int(batch.Int64()) {
		op := &common.Operation{
			Type:  common.OperationTypeKeygenInput,
			Curve: common.CurveSecp256k1ECDSABitcoin,
		}
		op.Id = common.UniqueId(reqId, fmt.Sprintf("%8d", i))
		op.Id = common.UniqueId(op.Id, fmt.Sprintf("MTG:%v:%d", signers, threshold))
		extra := op.Encode()
		common.AESEncrypt(aesKey[:], extra, op.Id)

		assert.Equal(oids[i], op.Id)
		nextId := common.UniqueId(genesis, op.Id)
		assert.Equal(tids[i], nextId)
	}
}
