# TEE Integration

## Overview
A trusted execution environment (TEE) is an environment isolated from the operating system. TEEs provide security guarantees about confidentiality and integrity of the code and memory executed inside them.

For the MPC network, the security guarantees provided by TEEs are attractive for two reasons:
1. They relax the threat models (e.g. honest-but-curious instead of malicious adversaries). This allows the adoption of significantly more efficient MPC protocols.
2. They help enforce backward secrecy. Since TEEs can guarantee that former nodes never gain lasting possession of plaintext secret-shares, collusion attacks after departure become infeasible.

TEEs provide their security guarantees by restricting how anything outside of the TEE can interact with the code running inside the TEE. This is great to protect against malicious actors, but it also restricts the honest actors. It has to be expected that debugging and handling of emergencies will become much more difficult compared to running an MPC node outside of a TEE.

This is a good moment to remind the reader that threshold cryptography requires threshold operational nodes. Anything less than that, and the protocol stalls, in which case, no funds can be moved.

Therefore, Near-One will roll-out its TEE implementation in two phases:
- Soft Launch: All mainnet nodes are running within TEEs. Their key shares are backed-up outside of the TEE.
- Hard Launch: All mainnet nodes are running within TEEs. Their key shares are backed-up inside a different TEE.

In order to protect the network from the worst case scenario (complete loss of funds due to loss of key shares or an incapacitated network), a disaster recovery plan is prepared.

## Disaster Recovery on a high-level
Disaster recovery is a plan intended to prevent a permanent loss of the signing quorum.
As long as the secret shares of the MPC nodes are securely backed-up outside of the TEE environment in which the node is running, it is highly likely that the network will be able to recover from otherwise catastrophic events. Therefore, each operator of an MPC node will be required to operate their own backup service alongside their node.

The backup service is intended to securely store a backup of the secret shares belonging to the same operator node.

The disaster recovery plan encompasses two steps:
1. Backup Generation: export the secrets from the node running inside the TEE to the backup service a secure manner.
2. Recovery from an otherwise catastrophic event: securely import the private keys from the backup service into the node running inside a TEE.

### Requirements

The backup service must:
- have a current view of the NEAR blockchain;
- ensure it securely holds a copy of the secret keys belonging to the MPC node;
- provide its copy to the node in case of need and do so in a secure manner;
- ensure it provides the copy only to a node that belongs to the same node operator.
- For the hard launch, the backup service will be required to run inside a TEE.

The node must:
- ensure it only exports encrypted shares to its designated backup service.
- ensure it only imports encrypted shares from its designated backup service.

In the context of disaster recovery, the MPC contract is used as a consensus layer between node operator, node and backup service.

### Execution
1. Backup generation:
    1. The node running inside the TEE and the backup service agree on a key used to encrypt the secrets.
    2. The backup service requests the secret shares from the node via a web endpoint.
    3. The node responds with the encrypted secret shares.

2. Recovery:
    1. The node running inside the TEE and the backup service agree on a key used to encrypt the secrets.
    2. The backup service submits the secret shares to a web-endpoint of the node.

### Effects on the MPC network
Backup generation and recovery can take place at the discretion of each node operator.
There is a dedicated section explaining how to use this mechanism to move a node from one machine to another and include it in the MPC network.


## Implementation Details

### Cryptography: agreeing on an encryption key
A pair-wise key establishment scheme can be leveraged to establish a symmetric key. A suitable implementation can be found in [libsodium](https://doc.libsodium.org/) and its rust wrapper [libsodium-rs](https://docs.rs/crate/libsodium-rs/latest). Specifically, the **key exchange protocol based on X25519** would be a good fit for the given set-up (c.f. [libsodium](https://doc.libsodium.org/key_exchange) and [libsodium-rs](https://docs.rs/libsodium-rs/latest/libsodium_rs/crypto_kx/index.html)).

The key establishment scheme requires that the node as well as the backup service have *mutually authenticated Curve25519 public keys*. The NEAR blockchain can be leveraged for this, more specifically, for each backup generation or recovery, the node and the backup service generate ephemeral keys on the `Curve25519` and publish them on the MPC smart contract. The node and the backup service can then each run a key generation protocol using their private key and the public key of the other party. 

_Note: The curious reader might ask why this protocol does not simply use the NEAR public/private key pairs associated to the MPC node and the backup service. The reason for this is is twofold:_
_- those keys are meant for signature generation._
_- While it is true that Curve25519 used in X25519 and edwards25519 used by the NEAR blockchain are [birationally equivalent](https://crypto.stackexchange.com/questions/43013/what-does-birational-equivalence-mean-in-a-cryptographic-context), so one could theoretically convert the NEAR account keys and use them for `X25519`, it is generally advised to use one key per application. This also allows us to use ephemeral keys, as opposed to static keys for the encryption. Which is desirable._

### Communication between the backup service and the MPC node
The **MPC node** will expose a web endpont over which the backup service can submit requests. It will need to be protected through some authentication mechanism.
The **backup service** will need to submit requests to the nodes web endpoint.

### Role of the Contract
The contract is used as a point of reference for the backup service and the MPC node during BAckup and Recovery phases.
Additionally, the contract is responsible for coordinating the recovery on the MPC-network level.

The contract is:
- used by the backup service:
    - to publish their details:
        - an ephemeral public key for key exchange between itself and the node
        - a static public key for transactions on the blockchain
        - their TEE attestation if applicable
    - to verify they are sending shares to the correct node
- used by the node:
    - to verify authenticity of the backup service
    - to publish an ephemeral public key for key exchange between itself and the node
- used by the node operator:
    - to approve a backup service for their node, by approving a NEAR account public key associated with the backup service.
- responsible for coordinating the MPC network throughout a recovery process (c.f. further below). 

_Note: In this document, the term node operator refers to a person operating a node that is acting as a participant in the MPC network. That person has a unique `AccountId` (an account on the NEAR blockchain) associated to its node. Without loss of generality, we assume that a node operator only operates a single node and that their `AccountId` serves as a unique identifier for the node as well as the operator._


### MPC network during a recovery process
Currently, the MPC network allows three protocol states:
- `Initializing` for generating new key shares
- `Running` when handling signature request
- `Resharing` when the network is resharing their secret keys for a change of the participant set, or for a change in the cryptographic threshold

Until now, when a node operator wanted to switch their machine, they needed to do so through a `Resharing` - they had to leave the network and then re-join.
Unfortunately, it may not be possible to use the same mechanism for recovering from disaster, as by definiton, a disaster implies that the network lost it signing quorum and thus, its agency.
To account for this, a fourth protocol state must be introduced: `Recovery`.

The purpose of this state is to:
- allow participants to change their participant information (e.g. tls keys, ip addresse, and anything other than their account id);
- allow a node to activate the Recovery mechanism and request the back-up share from the backup service.

This protocol state may:
- only be entered from `Running` or `Recovery` states.
- resume in a `Running` state, only if all participants have a valid key share of the current epoch.
- resume in a `Resharing` state under the same conditions under which the `Resharing` state could be resumed from a `Running` state.
- not resume in a state different to `Recovery`, `Running` or `Resharing`.

Unlike the `Resharing` state, entering this state does not require `threshold` votes, but rather, a single vote is sufficient. However, the `AccountId` of all participants must be preserved. Only secondary participant details may be changed.

In a first iteration, it is okay if signature requests are not accepted while the protocol is in `Recovery` state.

### Components **(This section is heavy WIP)**

#### Backup service
- For the hard-launch, the backup service will need to run inside a TEE and must pass attestation verification on the contract.
- The backup service runs an indexer which monitors the smart contract state on the blockchain.
- The backup service generates the following keys:
    - a static NEAR key, which the operator adds as an access key to their account id (note: with restrictions to specific contract methods).
    - an ephemeral key for the X25519 protocol. A new key is generated for each Backup or Recovery operation. The backup service submits this key to the smart contract.

##### Init
1. generates access key.
2. Generates attestation and submits its information to the smart contract (after being added by the node operator).

##### Backup Behavior
1. If the back-up server has secret shares from a different keyset than the current one in the smart contract, then it submits a request to the MPC node to receive a backup.

##### Recovery Behavior
1. The backup service monitors the contract state for any calls to `request_backup(participant_recovery_id, x25519_pk)`
2. If the call was done by the node for which this service is responsible, then the backup service:
    a. Generates a new X25519 keypair and submits their public key to the contract via `submit_backup_pk(x25519_pk, participant_recovery_id)`.
    b. Encrypts the keyshares with their private key and the public key submitted by the node, following the cryptographic protocol outlined below. 
    c. Submits the encrypted keyshares to the nodes http endpoint.
    d. Submits a `submitted_back_up(participant_recovery_id)` to the contract.

#### Node
The **MPC node** will expose a web endpont over which the backup service can submit requests. These endpoints require some sort of authentication _(yet to be specified)_.
The exposed endpoints are:
- GET /shares_backup - with an authentication header
    - Returns the encrypted shares, if a valid backup service is registered.
- POST /shares_recover
    - Posts encrypted shares to a new node.

##### Init
The node submits their attestation info.
##### Backup Generation
The node verifies the request is by the backup service. The node engages in the key exchange protocol.

##### Backup Recovery Behavior:
If the node is without keyshares, but a member of the current `Running` protocol state, then:
- it calls `request_recovery`
- it waits for the backup service to submit the secrets to the web endpoint.
- once received, it calls `recovered_backup`

##### Recovery Protocol State behavior:
- if it has secret shares of the current keyset:
    - engages in the sanity check 
    - votes `vote_recovered`
- else:
    - should not be part of the participant set.


#### Contract
_Note: types are wip_
The contract exposes additional endpoints:
- `request_recovery(participant_info: ParticipantInfo, x25519_pk)`:
    - The Near public key signing the transaction must be the access key of an existing participant.
    - Can be called only in `Running` or `Recovery`.
    - The submitted `participant_info` contains an attestation, as well as necessary operatinal details (c.f. current `ParticipantInfo` struct), which gets verified and stored in a map `RecoveryPaticipantInfo`.
        - The map `RecoveryParticipantInfo` has key `AccountId` (the near account of the participant) and value `(participant_recovery_id: u64, participant_info: ParticipantInfo, node_pk: NearPublicKey, x25519_pk: Curve25519PublicKey)` . `participant_recovery_id` is a unique id.
    - The call to `request_recovery` spawns a promise that is resolved by `submit_backup_pk` or a timeout.
        - Upon timeout, the entry is removed from `RecoveryParticipantInfo`.
            - if `RecovereyParticipantInfo` is empty and `RecoveredParticipantsReady` is non-empty, then the contract enters `Recovery` mode:
                - any participant that is in the current protocol state is also participant of the new `Recovery` protocol state.
                - if any participant has information stored in `RecoveredParticipantsReady`, then that information replaces any existing information of the same participant.
- `submit_backup_pk(x25519_pk, participant_recovery_id)`:
    - Can be called only in `Recovery` or `Running` protocol state.
    - This method can only be called by the access key belonging to the backup service.
    - The contract verifies that `participant_recovery_id` is found in the corresponding `RecoveryParticipantInfo` entry and rejects the call otherwise.
    - resumes the promise spawned by `request_recovery` and spawns a new promise that can only be resolved by `recovered_backup()`
        - Upon timeout, the entry of the associated `AccountId` is removed from `RecoveryParticipantInfo`.
            - if `RecovereyParticipantInfo` is empty and `RecoveredParticipantsReady` is non-empty, then the contract enters `Recovery` mode:
                - any participant that is in the current protocol state is also participant of the new `Recovery` protocol state.
                - if any participant has information stored in `RecoveredParticipantsReady`, then that information replaces any existing information of the same participant.
- `recovered_backup(partipant_recovery_id)`:
    - Can only be called by the node in `RecoveryParticipantInfo`
    - Can only be called in `Recovery` or `Running` state.
    - Resolves the promise from `submit_backup_pk`
    - removes the associated entry from `RecoveryParticipantInfo` and into a new map `RecoveredParticipantsReady`
        - if `RecovereyParticipantInfo` is empty and `RecoveredParticipantsReady` is non-empty, then the contract enters `Recovery` mode:
            - any participant that is in the current protocol state is also participant of the new `Recovery` protocol state.
            - if any participant has information stored in `RecoveredParticipantsReady`, then that information replaces any existing information of the same participant.
- `vote_recovered(keyset, participant_recovery_id)`: this endpoint can be called only by current participants of the `Recovery` protocol state. Once all participants called it, then the contract resumes `Running` state.
- `submit_recovery_info(recovery_attestation_info)`:
    - Can be called in any state. Includes an attestation. Used to authenticate the backup service.
- `whitelist_recovery_service(account_pk)` (called by operator) // this could be optional. Access Key might be proof enough


## Materials:
https://nearone.slack.com/archives/C07UW93JVQ8/p1753830474083739
NIST SP 800-56A https://csrc.nist.gov/pubs/sp/800/56/a/r3/final
https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar3.pdf - page 105 - 106

