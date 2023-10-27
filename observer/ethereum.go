package observer

import "github.com/MixinNetwork/safe/keeper"

func (node *Node) ethereumParams(chain byte) (string, string) {
	switch chain {
	case keeper.SafeChainEthereum:
		return node.conf.EthereumRPC, keeper.SafeEthereumChainId
	case keeper.SafeChainMVM:
		return node.conf.MVMRPC, keeper.SafeMVMChainId
	default:
		panic(chain)
	}
}
