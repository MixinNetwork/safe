# Safe Computer

Safe Computer is a decentralized computer for financial computing. This computer runs inside Mixin Safe, and utilizes existing mature blockchains as the runtime.

## Spec

Send transactions to the computer group, each transaction costs some XIN, could be multiple outputs or a XIN transaction references the previous transactions.

It's better to increase the maximum references count in Mixin Kernel.

With transaction extra to determine the 2 operation.

The extra must be base64 URL encoding.

## Add a User

Assign a unique unsigned integer UID for a MIX address. Also makes a user account on Solana. The account is fully controlled by the group account.

1 | MIX

The UID is bigger than 2^48. Smaller UID is the system user. But the UID is never smaller than 2^32.

## Make System Calls

One transaction could make one system call.

2 | UID(uint64) | Solana Encoded Tx

UID is the asset recipient, and a invalid UID or non existing UID will lose the assets.

## Solana Runtime

A MIX account wants to create BTC/SOL pool to the Raydium program.

1. Send XIN transaction with extra to computer group to add a User. Then query the HTTP API to get the UID, e.g. 432483921937, and information to build transaction on Solana, including fee payer address, user account address and assigned nonce account with hash on Solana Network.
2. Build the Solana transaction with fee payer, nonce account hash, and  instruction to create pool on Raydium.
3. Send three transactions to the computer group. BTC, SOL, and XIN references the two transactions, with extra: 2 | 432483921937 | Solana Encoded Tx

The XIN transaction to create System Call may have the memo exceeds the length limit. It could be done by sending the storage transaction with the first output as a storage output to burn the XIN, and the second output to computer group.

The group receives the XIN transaciton and will check the fee is enough, then make system calls according to the extra.

The user and the group both have an account on Solana Chain, and are controlled by the MPC multisig. The group withdraws SOL to the user account at first. After the SOL withdrawal is confirmed by Solana blockchain, the observer sends a notification to the group and then send a transaction to group to create a new preparing system call to mint BTC to the user account with another spare nonce account controlled by the group. The transaction created by observer should be with the following instructions:

1. advance nonce
2. transfer SOL to user account
3. create the spl token of BTC if necessary
4. create the associated token address of user account if necessary
5. mint spl token of BTC to user account

After the transaction that transfered and minted the assets is confirmed, the observer should update the hash of used nocne account and sends a notification to the group. Then requests the group to sign the system call created by user.

Then each group members sign the transaction in one go, combines the signature and wait observer to send it to the network. To combine the signature, each node sends a transaction to the group. And there is a member signature to the data for the group to check. 

After the transaction confirmed, there should be LP tokens in the user account and maybe some BTC because of slippage. We have an observer node to scan the Solana blockchain and finds the extra and rest tokens in user account after System Call. The observer will create a postprocess system call to the computer group, which should be with the following instructions:

1. advance nonce.
2. user account transfer LP token to the group account deposit address in Mixin.
3. user account burns the left BTC token.

Then sign the transaction in one go, and broadcast, and marking the transaction in pending state. The observer finds the transaction successful, then send a notification to the group. The group will sends BTC to the user MIX account, but not the LP token.

Whenever the group account received a mixin deposit transaction, in this case, the LP token, the observer will send a notification to the group, and the group will just send the LP token to the user account corresponding UID MIX account.

The observer is one member of the computer group. And any member could be the observer. There could be multiple observers, and the observer notifications could be duplicated, but the group could identify it because the notification is just a Solana transaction hash.

## Concensus

It's very important that the computer group never makes any transactions based on external environment. It will only makes transactions or signatures based on Mixin output, either from users or from observers.

The observer sends notifications with Solana transactions, it's external information for the group, but this computer has an assumption that Solana will not fork, a Solana transaction is finalized and should be there. So an observer notified solana transaction is considered determinstic fact, but the tranaction must be an observer notification at first. So if the observer is honest, then all group members will find the same transaction in the Solana blockchain, and if can't find it, the group member should just panic. Then it means either the observer is adversary or the Soalan blockchain is broken.

It's also very important that the group account in Solana or user accounts, they don't pay any fee, the fee should be paid by the fee account, thus ensure the group and user accounts balance are always valid.
