# Boot Mixin Safe

Mixin Safe is composed of two networks, Mixin Safe Signer and Mixin Safe Keeper, both are MTG of existing Mixin Kernel nodes.

## Preparation

Both Signer and Keeper MTG rely on some external blockchain RPC nodes to operate:

1. Bitcoin
2. Litecoin
3. Mixin Virtual Machine
4. Mixin Kernel

### Bitcoin

Get Bitcoin Core 25.0+, and enable `txindex=1` for `getrawtransaction` RPC.

Then boot bitcoind and wait for it to fully synchronized.

### Litecoin

Same to Bitcoin.

### Mixin Virtual Machine

Download the latest `geth` then follow the [private network](https://geth.ethereum.org/docs/fundamentals/private-network) guide.

The genesis.json file for Mixin Virtual Machine is as below:

```json
{
  "config": {
    "chainId": 73927,
    "homesteadBlock": 0,
    "eip150Block": 0,
    "eip155Block": 0,
    "eip158Block": 0,
    "byzantiumBlock": 0,
    "constantinopleBlock": 0,
    "petersburgBlock": 0,
    "istanbulBlock": 17650000,
    "berlinBlock": 17660000,
    "londonBlock": 17670000,
    "clique": {
      "period": 1,
      "epoch": 30000
    }
  },
  "difficulty": "1",
  "gasLimit": "8000000",
  "extradata": "0x0000000000000000000000000000000000000000000000000000000000000000f3d5a53f8ebc6787464fdf0b7e8cc43ce4fa9d7a3285edbd1701fac870997d7b9ed41fd188f66f1d36f1237df28cea66510bcadb7453c3cdf2e2ee0c0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
  "alloc": {
    "f3d5a53f8ebc6787464fdf0b7e8cc43ce4fa9d7a": { "balance": "1000000000000000000000000" }
  }
}
```

Boot the geth node with following parameters:

```bash
#!/bin/sh

/usr/local/bin/geth \
    --networkid 73927 \
    --datadir /var/data/geth \
    --syncmode full \
    --gcmode archive \
    --maxpeers 100 \
    --port 30303 \
    --http \
    --http.addr '0.0.0.0' \
    --http.port 8545 \
    --http.corsdomain '*' \
    --http.api 'eth,net,web3,personal,admin,txpool,debug' \
    --http.vhosts '*' \
    --ws \
    --ws.addr '0.0.0.0' \
    --ws.port 8546 \
    --ws.origins "*" \
    --ws.api "eth,net,web3,debug,txpool" \
    --bootnodes 'enode://e662c1d95f81d1c5cc1a0e53a1b48a9cfc1ddcc52fa0ea58f75ffa407e7e4f52b4a3126ee0349173c3422a737cca8df66fb6aa1a98a71f757c79c57a71de01a6@34.67.105.90:30303,enode://610cc4c968218f39e184dcbacd06cb8f4e43167d1c5ac7c1c0bd06f441d0ee2f1f01637000f2bbf429971a2787311f30c4228fc01d050359e82482d4f11a5f19@34.69.152.102:30303'
```

### Mixin Kernel

Run an archive only Mixin Kernel full node with a random private key. There is a [simple guide](https://developers.mixin.one/docs/mainnet/guide/full-node-join).


## Mixin Safe Signer

Mixin Safe Signer is the MPC network that does all DKG and signature aggregation works.

- The node is required to be isolated from the Internet as much as possible, because it keeps shares of all private keys.
- The node data must have hourly backup enabled, because private key share loss may cause punishment to the corresponding Mixin Kernel node pledge.
- The node should enable secure disk encryption if it's in a cloud environment.

With requirements above satisfied, it's easy to boot the signer node. Prepare a place for the data, i.e. `/var/mixin/safe/signer`, then modify the config.toml below according to the node app.

```toml
[signer]
store-dir = "/var/mixin/safe/signer"
# the mixin messenger group conversation id for signer communication
messenger-conversation-id = "d40eda10-ff3c-4a1d-929d-83a96b1e2137"
# the mpc threshold is recommended to be 2/3 of the mtg members count
threshold = 2
# a shared ed25519 private key to do ecdh with the keeper
shared-key = "128106b2b9815f839d84f6e7cf63b403a2fd1aa0264af858be649873f47f8809"
# the asset id that each signer node send result to signer mtg
asset-id = "44d7de8f-5533-36f8-8b04-d3674baf5851"
# the asset id that the keeper send operations to the signer mtg
# this asset must be fully controlled by the keeper mtg
keeper-asset-id = "db6a8603-00c1-38fd-8ebb-b741f358cac7"
# the keeper ed25519 public key to do ecdh with the shared key
# and this key is used to verify the signature of all operations
keeper-public-key = "5662c910613f3db30b3acd0092655d4fc301b1d0cc0d472ee03acf411d30d99c"
mixin-rpc = ""

[signer.mtg.genesis]
members = [
  "a6f3e429-c278-469f-ab3f-5a4e4ee7625f",
  "ca9af3fc-f5f2-46a7-b6f7-fb8ba8534afc",
  "1a635674-4abd-4735-b209-fac05f5a8ea2",
  "f2aa91b7-01fc-4c42-85ef-a4dcda976615",
]
# the mtg threshold must not be smaller than the mpc threshold
threshold = 4
timestamp = 1676276828135856241

[signer.mtg.app]
client-id = ""
session-id = ""
private-key = ""
pin-token = ""
pin = ""
```

Basically, the `store-dir`, `mixin-rpc` and `mtg.app` section need to be added accordingly, then boot the Mixin Safe Signer node.

```
safe signer -c /var/mixin/safe/signer/config.toml
```

## Mixin Safe Keeper

Mixin Safe Signer network only accepts MPC requets carried by a specific Mixin Kernel asset, this asset is managed by Mixin Safe Keeper network.

Mixin Safe Keeper network doesn't store any MPC private keys, but it's still important to keep the node isolated from the Internet as much as possible.

It's recommended to keep Mixin Safe Keeper node isolabed from the Mixin Safe Signer node as well, and follow the same backup procedure.

The node needs a similar configuration file as the Signer node, just modify the template below.

```toml
[keeper]
store-dir = "/var/mixin/safe/keeper"
# a shared ed25519 private key to do ecdh with signer and observer
shared-key = "9b2b94d3259c564fd2bab8fc4ba648f0ccb4ce8c9f30e7bfadec29d387ccb10d"
# the signer ed25519 public key to do ecdh with the shared key
# and this key is used to verify the signature of all responses
signer-public-key = "60d222d5587e4f5024e782b4ad1b46b8afb152130ea0e244dffd31f8e9be8224"
# the asset id that the keeper send operations to the signer mtg
# this asset must be fully controlled by the keeper mtg
asset-id = "db6a8603-00c1-38fd-8ebb-b741f358cac7"
# the asset id that the observer send requests to the keeper mtg
# this asset must be fully controlled by the observer
observer-asset-id = "bb7da686-2a6b-3dc7-a559-762b1255804e"
# the observer ed25519 public key to do ecdh with the shared key
# and this key is used to verify the signature of all requests
observer-public-key = "ff3fd39ef322445827794325bdf2202a7b5fb88d23b6572a710cd8eda558e7a5"
# the observer is good to be a single user
observer-user-id = "1050c460-b483-4b1b-bf2f-ccdbe910f7a5"
mixin-messenger-api="https://api.mixin.one"
mixin-rpc = ""
bitcoin-rpc = ""
litecoin-rpc = ""
mvm-rpc = ""

[keeper.mtg.genesis]
# it is not necessary to include all signer mtg members here,
# but it is recommended to do that, and the observer id must be
# included in the keeper mtg members.
members = [
  "a6f3e429-c278-469f-ab3f-5a4e4ee7625f",
  "ca9af3fc-f5f2-46a7-b6f7-fb8ba8534afc",
  "1a635674-4abd-4735-b209-fac05f5a8ea2",
  "f2aa91b7-01fc-4c42-85ef-a4dcda976615",
  "1050c460-b483-4b1b-bf2f-ccdbe910f7a5",
]
# the mtg threshold is recommended to be 2/3 of the members count
threshold = 4
timestamp = 1676276828135856241

[keeper.mtg.app]
client-id = ""
session-id = ""
private-key = ""
pin-token = ""
pin = ""
```

Basically, the `store-dir`, `mtg.app` and all `rpc` section need to be added accordingly, then boot the Mixin Safe Keeper node.

```
safe keeper -c /var/mixin/safe/keeper/config.toml
```
