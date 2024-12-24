# Safe Computer

Safe Computer is a decentralized computer for financial computing. This computer runs inside Mixin Safe, and utilizes existing mature blockchains as the runtime.

## Spec

Send transactions to the computer group, each transaction costs some XIN, could be multiple outputs or a XIN transaction references the previous transactions.

It's better to increase the maximum references count in Mixin Kernel.

With transaction extra to determine the 3 operation.

The extra must be pure bytes, or base64 URL encoding.

## Start a Process

Assign a unique unsigned integer PID for an existing program in a supported runtime.

0 | ADDRESS

The PID is bigger than 2^24. Smaller PID is the system process.

## Add a User

Assign a unique unsigned integer UID for a MIX address. Also makes a user account on Solana. The account is fully controlled by the group account.

1 | MIX

The UID is bigger than 2^48. Smaller UID is the system user. But the UID is never smaller than 2^32. Thus make the PID and UID globally unique in the system.

## Make System Calls

A transaction could make multiple system calls to multiple processes.

2 | UID(uint64) |
PID(uint32) | CALLDATA(0:LEN-PREFIXED-BYTES OR 1:HASH) |
PID(uint32) | CALLDATA(0:LEN-PREFIXED-BYTES OR 1:HASH) |
...

UID is the asset recipient, and a invalid UID or non existing UID will lose the assets.

It's possible to deploy a program in a supported runtime, just make a system call to the runtime PID, with the program bytes as the CALLDATA. This is undefined yet, need to discuss. Better not doing this.

## Solana Runtime

A MIX account wants to add BTC/SOL pool to the Raydium program, the PID is 3278432.

1. Add a User and query the HTTP API to get the UID, e.g. 432483921937. Now there must already be the solana user account.
2. Send three transactions to the computer group. BTC, SOL, and XIN references the two transactions, with extra:
3. 2 | 432483921937 | 3278432 | BTC/SOL WHAT WHAT

The group receives the XIN transaciton and will check the fee is enough, then make system calls according to the extra.

The group has a group account, controlled by the multisig. The group withdraws SOL to the group account. After the SOL transaction is confirmed by Solana blockchain. The observer sends a notification to the group. Then the group makes a transaction with the following instructions:

1. group account mint BTC to the user account
2. group account sends SOL to the user account
3. user account adds SOL and BTC to Raydium
4. advance nonce, this nonce account is controlled by the group too

Then each group members sign the transaction in one go, and combines the signature and sends to the network. To combine the signature, each node sends a storage transaction, with 0.0000001XIN output to the group. And there is a member signature to the data for the group to check. If the transaction extra is small enough, we just sends a normal XIN transaction, without storage output.

After the transaction confirmed, there should be LP tokens to the user account? To make this more complicated, the transaction also refunds some BTC because of slippage. We have an observer node to scan the Solana blockchain and finds this LP and BTC transaction to the user account, and sends a notification to the computer group. The computer group will make a transaction with the following instructions:

1. user account transfer LP token to the group account deposit address in Mixin.
2. user account burns the BTC token.
3. advance nonce.

Then sign the transaction in one go, and broadcast, and marking the transaction in pending state. The observer finds the transaction successful, then send a notification to the group. The group finds the transaction failed or succesful. If failed, then mark the transaction failed and do nothing. The observer could send a retry notification, or send a refund transaction so that the group will just refund everything to the MIX address. If successful, then the group will sends BTC to the user MIX account, but not the LP token.

Whenever the group account received a mixin deposit transaction, in this case, the LP token, the observer will send a notification to the group, and the group will just send the LP token to the user account corresponding UID MIX account.

The observer is one member of the computer group. And any member could be the observer. There could be multiple observers, and the observer notifications could be duplicated, but the group could identify it because the notification is just a Solana transaction hash.

## Concensus

It's very important that the computer group never makes any transactions based on external environment. It will only makes transactions or signatures based on Mixin output, either from users or from observers.

The observer sends notifications with Solana transactions, it's external information for the group, but this computer has an assumption that Solana will not fork, a Solana transaction is finalized and should be there. So an observer notified solana transaction is considered determinstic fact, but the tranaction must be an observer notification at first. So if the observer is honest, then all group members will find the same transaction in the Solana blockchain, and if can't find it, the group member should just panic. Then it means either the observer is adversary or the Soalan blockchain is broken.

It's also very important that the group account in Solana or user accounts, they don't pay any fee, the fee should be paid by the fee account, thus ensure the group and user accounts balance are always valid.

Because of the transaction size limit of Solana blockchain, we make a 4/7 MTG for the computer. We also must use the address lookup table and version 0 transaction, just add the 7 members and the group account to the lookup table? Then change the authority or signer of the lookup table to the group account itself?
