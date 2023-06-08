# Mixin Safe Governance

This app serves as a suite of tools to make it easy for Mixin Kernel nodes to participate in the Mixin Safe network.


## Consensus

All Mixin Kernel nodes should serve as Mixin Safe nodes, this is incentivized instead of being enforced. The Mixin Network daily mint will include a new category named custodian incentive, together with kernel and light node incentives. After Mixin Safe network launched, the mint distribution will change to kernel 50%, custodian 40% and light node 10%, from kernel 90% and light node 10%.

Besides the signer and payee key, each Mixin Kernel node must prepare a custodian key to receive the custodian incentives. Custodian incentives are distributed to all custodian nodes daily prorated to their works of making successful Mixin Safe transaction signatures. A Mixin Safe node must stay as Mixin Kernel node, and must produce at least one Mixin Kernel and Mixin Safe signature per week respectively.

The custodian key will be registered to Mixin Kernel by the Mixin Safe network whenever a new node accepted to Mixin Safe. When Mixin Safe network launched, the genesis Mixin Domain will register all genesis Mixin Safe nodes to Mixin Kernel in a single custodian pledge transaction. Each accepted Mixin Kernel node needs to burn a fixed 100XIN to join Mixin Safe network and won't be refunded under any circumstances.

All Mixin Safe nodes will be assessed by Mixin Kernel constantly, and all light nodes are also incentivized to test Mixin Safe nodes with a small fee to ask for a signature. A Mixin Kernel node may be completely slashed if the corresponding Mixin Safe node failed to produce a transaction or verification signature.


## Preparation

Mixin Safe nodes use Mixin Messenger protocol to communicate with each other, this provides extremely high security protection by isolating all Mixin Safe nodes from the open Internet. Since Mixin Kernel has a maximum 50 nodes capacity, so the governance app will provide 50 Mixin Messenger apps to act as the Mixin Safe node candidates and they will share a same Mixin Messenger group.

Each Mixin Kernel node which expects to serve as a Mixin Safe node needs to pay the governance app 100XIN to claim an app. This claim transaction must include as extra the Mixin Kernel node id, custodian public key, signatures of both Mixin Kernel signer and payee key. And from this on, all Mixin Kernel nodes must use a unique payee key to maintain the unique relationship with their Mixin Safe nodes.

Once the registration transaction validated, the governance app will send a transaction with as extra the Mixin Messenger app private key, all encrypted by the custodian public key. Then the node candidate can decrypt this information, and change both the app private key and app owner.


## Roadmap

The governance app will be open for registration from the 7th July, 2023, and open until 8th Aug, 2023. All Mixin Kernel nodes can use the governance registration tool to claim a seat in the Mixin Safe genesis launch. Besides thorough security technology background, the only mandatory requirements are 100XIN and a custodian key.

On the 8th Aug, 2023, Mixin Safe network will be registered to Mixin Kernel, and mint distribution will start in the new model the next day. We don't expect to accept new Mixin Safe nodes registration within at least 6 months due to technology development maturity.
