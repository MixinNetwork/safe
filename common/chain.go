package common

import (
	"github.com/MixinNetwork/safe/apps/bitcoin"
	"github.com/MixinNetwork/safe/apps/ethereum"
)

const (
	SafeChainBitcoin  = bitcoin.ChainBitcoin
	SafeChainLitecoin = bitcoin.ChainLitecoin
	SafeChainEthereum = ethereum.ChainEthereum
	SafeChainPolygon  = ethereum.ChainPolygon

	SafeBitcoinChainId  = "c6d0c728-2624-429b-8e0d-d9d19b6592fa"
	SafeEthereumChainId = "43d61dcd-e413-450d-80b8-101d5e903357"
	SafeLitecoinChainId = "76c802a2-7c88-447f-a93e-c29c9e5dd9c8"
	SafePolygonChainId  = "b7938396-3f94-4e0a-9179-d3440718156f"
	SafeSolanaChainId   = "64692c23-8971-4cf4-84a7-4dd1271dd887"
)

func SafeCurveChain(crv byte) byte {
	switch crv {
	case CurveSecp256k1ECDSABitcoin:
		return SafeChainBitcoin
	case CurveSecp256k1ECDSALitecoin:
		return SafeChainLitecoin
	case CurveSecp256k1ECDSAEthereum:
		return SafeChainEthereum
	case CurveSecp256k1ECDSAPolygon:
		return SafeChainPolygon
	default:
		panic(crv)
	}
}

func SafeChainCurve(chain byte) byte {
	switch chain {
	case SafeChainBitcoin:
		return CurveSecp256k1ECDSABitcoin
	case SafeChainLitecoin:
		return CurveSecp256k1ECDSALitecoin
	case SafeChainEthereum:
		return CurveSecp256k1ECDSAEthereum
	case SafeChainPolygon:
		return CurveSecp256k1ECDSAPolygon
	default:
		panic(chain)
	}
}

func SafeChainAssetId(chain byte) string {
	switch chain {
	case SafeChainBitcoin:
		return SafeBitcoinChainId
	case SafeChainLitecoin:
		return SafeLitecoinChainId
	case SafeChainEthereum:
		return SafeEthereumChainId
	case SafeChainPolygon:
		return SafePolygonChainId
	default:
		panic(chain)
	}
}

func SafeAssetIdChain(chainId string) byte {
	id := SafeAssetIdChainNoPanic(chainId)
	if id > 0 {
		return id
	}
	panic(chainId)
}

func SafeAssetIdChainNoPanic(chainId string) byte {
	switch chainId {
	case SafeBitcoinChainId:
		return SafeChainBitcoin
	case SafeLitecoinChainId:
		return SafeChainLitecoin
	case SafeEthereumChainId:
		return SafeChainEthereum
	case SafePolygonChainId:
		return SafeChainPolygon
	}
	return 0
}
