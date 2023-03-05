# safe

A multiplex cold wallet with multisig and MPC.


## Bitcoin

Manage a Bitcoin safe.


### Create safe

Send BTC to the MTG, with Bitcoin holder public key and Mixin receivers as memo.


### Receive

Transfer from anywhere to the safe Bitcoin address, then receive safeBTC to the Mixin receivers.


### Send

The safeBTC Mixin users, Bitcoin holder key, and the MTG need to sign the transaction together.

1. Send safeBTC to the MTG, with Bitcoin holder public key and recipient address as memo.
2. Safe will respond with the raw transaction.
3. Bitcoin holder signs the raw transaction.
4. Send transaction hash and holder signature to the MTG.
5. MTG sign the transaction and broadcast to Bitcoin network.

At the 3rd step, Bitcoin holder is able to revoke the raw transaction if he decides it's not they wants.


### Fee

Create safe costs 0.001BTC, and every transaction costs some BTC based on Bitcoin network condition. To spend something, deposit enough fee to a separate safe fee address at first.


```bash
$ bitcoin-cli getnewaddress safe legacy
1Enn5Lmtic21HibkwD83ct4DpEUDpLXh53

$ bitcoin-cli getaddressesbylabel safe
{
  "1Enn5Lmtic21HibkwD83ct4DpEUDpLXh53": {
    "purpose": "receive"
  }
}

$ bitcoin-cli getaddressinfo 1Enn5Lmtic21HibkwD83ct4DpEUDpLXh53
{
  "address": "1Enn5Lmtic21HibkwD83ct4DpEUDpLXh53",
  "scriptPubKey": "76a9149741fae4d58dd5787a313b50d2035bec1071666d88ac",
  "ismine": true,
  "solvable": true,
  "desc": "pkh([0b63fe77/44'/0'/0'/0/1]02221eebc257e4789e3893292e78c19d5feb7788397d511afb3ffb14561ade500a)#f0nu7uag",
  "parent_desc": "pkh([0b63fe77/44'/0'/0']xpub6BprQS4rPVtUMTmU49YTao9CXvMLxGKSDK1WKwLh9ab5zUKPRiSEF6YqYB6WyhrCCTmj5o76FnEfVJBzMjLToDSXWZQJrovpJYtJ3U1QgUv/0/*)#fzrrsva4",
  "iswatchonly": false,
  "isscript": false,
  "iswitness": false,
  "pubkey": "02221eebc257e4789e3893292e78c19d5feb7788397d511afb3ffb14561ade500a",
  "iscompressed": true,
  "ischange": false,
  "timestamp": 1674741486,
  "hdkeypath": "m/44'/0'/0'/0/1",
  "hdseedid": "0000000000000000000000000000000000000000",
  "hdmasterfingerprint": "0b63fe77",
  "labels": [
    "safe"
  ]
}

$ bitcoin-cli signmessage 1Enn5Lmtic21HibkwD83ct4DpEUDpLXh53 "mixin safe"
H3RKBE7bK/BoKoupbB7BC8fKeesHst3tLhfhNSkAPZ8XZuB3nE8YJRPx/6ZPI7PN9fsq2PrnfpETCEoLA8PHAfY=
```
