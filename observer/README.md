# Observer

One of the 2/(holder, signer, observer), and the observer is the last backup to sign a transaction and should never be used before that point.

Observer is a single user, belongs to the keeper MTG members. And it must be deployed independent of keeper and signer.

1. Generate observer public keys to keeper MTG.
2. Scan Bitcoin node to send deposit information to keeper MTG.
3. Estimate Bitcoin transaction fee to keeper MTG, it's better to use 10x the real fee to ensure confirmation.
