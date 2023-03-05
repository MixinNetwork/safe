# signer

The signer MTG receives operation requests from mixin kernel transactions, the operation is encoded in the `common/operation.go` format.

There are two types of operation requests available, and each operation should use a unique session id in the operation body.

1. `OperationTypeKeygenInput` requests the MTG to start a new MPC key generation.
2. `OperationTypeSignInput` requests the MTG to start a new MPC message signature.

Both operations may succeed or fail, and the signer MTG doesn't guarantee the success. If the operation succeeds, the signer MTG will respond the result with kernel transaction, otherwise, the signer MTG does nothing.

The requester can only assume the operation failed after around 10 minutes timeout, because the signer MTG won't respond. If the requester wants assurance of a successful operation request, it should have a mechanism to start a new operation request with a new session id.

## Security

The signer MTG authenticate operation requests through two methods:

1. The operation is encrypted by a shared AES key between the signer MTG and requester.
2. The signer MTG only accepts one valid mixin asset as the request transactions.

So the requester should keep the AES key safe and make sure nobody has access to the mixin asset.
