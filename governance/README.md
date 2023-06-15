# Mixin Safe Governance

This app serves as a suite of tools to facilitate participation of Mixin Kernel nodes in the Mixin Safe network with utmost ease.

## Consensus

All Mixin Kernel nodes should serve as Mixin Safe nodes, this is incentivized instead of being enforced. Custodian incentive will be introduced as a new category in the daily mint distribution of the Mixin Network. This way, Mixin Safe nodes will receive 40% of the mint, while the Kernel and light node incentives receive 50% and 10% respectively.

To participate, every Mixin Kernel node must prepare and have a custodian key in addition to the payee and signer key, in order to receive the custodian incentives. Each Mixin Kernel node must also use a unique payee key to maintain a distinct relationship with their Mixin Safe nodes. Furthermore, a Mixin Safe node must remain a Mixin Kernel node and produce at least one Mixin Kernel and Mixin Safe signature per week, respectively.

Whenever a new node is accepted to the Mixin Safe network, the custodian key will be registered with Mixin Kernel by the Mixin Safe network. The genesis Mixin Domain will register all genesis Mixin Safe nodes with Mixin Kernel in a single custodian pledge transaction. Every accepted Mixin Kernel node is required to burn a fixed 100XIN to join the Mixin Safe network. This amount cannot be refunded under any circumstances.

Mixin Kernel will continuously assess all Mixin Safe nodes, while all light nodes also have incentives to test and assess the Mixin Safe nodes by requesting a signature with a small fee. In the event of failure by the corresponding Mixin Safe node to produce a transaction or verification signature, a Mixin Kernel node may be completely slashed.

## Custodian

When Mixin Safe boots, Mixin Domain registered all the Safe nodes and all the safe nodes together will generate a Ed25519 Mixin Custodian key by FROST protocol. The Custodian key will be submitted to the Kernel with all Safe nodes signatures.

Afterwards, the mint distribution will be sent 40% to the Custodian key and Mixin Safe network will distribute the Custodian rewards towards the Safe work contributions of all nodes. And this custodian key will be responsible for future Custodian key update in the case of Safe nodes changed.

The Custodian key is also responsible to send the punishment or slash command to the Kernel whenever some bad behaviors detected either by the Safe network itself or by light nodes.

The Custodian key will do the Kernel deposits guardian together with the Domain, they must sign the deposit transaction together to make it final.

## Preparation

Mixin Safe nodes use Mixin Messenger protocol to communicate with each other, providing extremely high-security protection by isolating all Mixin Safe nodes from the open Internet. As Mixin Kernel has a maximum capacity of 50 nodes, the governance app will offer 50 Mixin Messenger apps to act as Mixin Safe node candidates, sharing a single Mixin Messenger group.

Every Mixin Kernel node that wishes to serve as a Mixin Safe node, register with the governance app and pay 100XIN to claim an app. This claim transaction must include as extra the Mixin Kernel node ID, payee key, custodian public key, and signatures of both Mixin Kernel signer and payee keys. Subsequently, all Mixin Kernel nodes must use a unique payee key to maintain a distinct relationship with their Mixin Safe nodes.

Upon validation of registration transactions, the governance app will send a transaction consisting of as extra the Mixin Messenger app private key, encrypted with the custodian public key. The node candidate can then decrypt this information and change both the app private key and app owner.

## Roadmap

The governance app registration tool will be open for registration from the 7th July 2023 until 8th Aug 2023. All Mixin Kernel nodes can register and claim a seat in the Mixin Safe genesis launch, with a mandatory requirement of 100XIN and a custodian key.

On 8th Aug 2023, Mixin Safe network will be registered with Mixin Kernel, and the custodian will receive a distribution of the mint beginning from the following day. We do not expect to accept new Mixin Safe nodes registration in at least six months due to the ongoing development progress.
