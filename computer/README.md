# Safe Computer

Safe Computer is a decentralized computer for financial computing. This computer runs inside Mixin Safe, and utilizes existing mature blockchains as the runtime.

## Spec

Send a XIN transaction to the computer group, and the XIN transaction could reference the previous transactions.

With transaction extra to determine the 2 operation.

The extra must be base64 URL encoding.

## Add a User

Assign a unique unsigned integer UID for a MIX address. Also makes a user account on Solana. The account is fully controlled by the group account.

1 | MIX

The UID is bigger than 2^48. Smaller UID is the system user. But the UID is never smaller than 2^32.

## Make System Calls

One transaction could make one system call.

2 | UID(uint64) | CALL ID (uuid) | Skip Flag (byte) | FEE ID (optional, uuid)

UID is the asset recipient, and a invalid UID or non existing UID will lose the assets.

CALL ID is a uuid and could be specified by creator.

When Skip Flag is set to 1, postprocess system call would not be proposed to refund rest assets or transfer newly received assets to MIX account.

When FEE ID is provided and extra amount of XIN is sent to computer, the same worth of SOL would be transfered to user account on Solana for rents to create accounts during the system call.

The bytes of Solana transaction should be saved in a storage transaction, and the storage transaction must be referenced by the XIN transaction to make System Call.

## Solana Runtime

A MIX account wants to create BTC/SOL pool to the Raydium program.

1. Send XIN transaction with extra to computer group to add a User. Then query the HTTP API to get the UID, e.g. 432483921937, and user account address.
2. Fetch fee payer address, nonce account address and nonce hash from HTTP API, then build Solana transaction with this fee payer address, nonce advance instruction and create pool insturctions.
3. Fetch fee id and amount of XIN for the same worth of SOL to pay the rents of created account needed in System Call.
4. Send the XIN transaction with 0.001 XIN for operation and extra amount of XIN for rents, and it should reference a storage transaction of Solana transaction, a BTC transaction and a SOL transaction for liquidity.

The group receives the XIN transaciton and will check referenced transactions, the amount of received fee, the payer and the nonce account of storaged Solana transaction, then build the prepare System Call to transfer SOL and mint BTC from group account to user account in preparetion for System Call created by user. And the mpc would start to generate the signatures for these two System Calls. The prepare System Call created by observer includes the following instructions:

1. advance nonce
2. transfer SOL for rent to user account
3. transfer SOL for liquidity to user account
4. create the associated token address of user account if necessary
5. mint spl token of BTC to user account

The user and the group both have an account on Solana Chain, and are both controlled by the MPC multisig. The group withdraws SOL to the group account at first. After the SOL withdrawal being confirmed by Solana blockchain, the observer sends a notification to the group. 

Then observer will send the prepare System Call and the user System Call in order with the generated signatures. After the two transaction are both confirmed, the observer should update the hashes of used nocne accounts and notify the group with a post-process System Call to burn the rest amount of BTC, transfer the rest amount of SOL and transfer the received LP token to the deposit entry of group. 

After the group mpc generates the signature of post-process signature, the observer node would send it to the Solana Network and notify the group when it is confirmed. The group would refund the same amount of BTC to the MIX account, and transfer the SOL and LP token to the MIX account after receiving the deposits.

In addition, the observer keeps scanning the Solana blocks, and would create a system call to transfer deposit to the user account. Whenever the group receives a mixin deposit transaction, in this case, the LP token, the group will just send the LP token to the MIX account.

The observer is one member of the computer group. And any member could be the observer. There could be multiple observers, and the observer notifications could be duplicated, but the group could identify it because the notification is just a Solana transaction hash.

## Concensus

It's very important that the computer group never makes any transactions based on external environment. It will only makes transactions or signatures based on Mixin output, either from users or from observers.

The observer sends notifications with Solana transactions, it's external information for the group, but this computer has an assumption that Solana will not fork, a Solana transaction is finalized and should be there. So an observer notified solana transaction is considered determinstic fact, but the tranaction must be an observer notification at first. So if the observer is honest, then all group members will find the same transaction in the Solana blockchain, and if can't find it, the group member should just panic. Then it means either the observer is adversary or the Soalan blockchain is broken.

It's also very important that the group account in Solana or user accounts, they don't pay any fee, the fee should be paid by the fee account, thus ensure the group and user accounts balance are always valid.
