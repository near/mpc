# TEE Integration

## Overview
A trusted execution environment (TEE) is an environment isolated from the operating system. It provides security guarantees about confidentiality and integrity of the code and memory executed inside.

For the MPC network, the security guarantees provided by TEEs are attractive for two reasons:
1. They relax the threat models (e.g. honest-but-curious instead of malicious adversaries). This allows the adoption of significantly more efficient MPC protocols.
2. They help enforce backward secrecy. Since TEEs can guarantee that former nodes never gain lasting possession of plaintext secret-shares, collusion attacks after departure become infeasible.

TEEs provide their security guarantees by restricting how anything outside of the TEE can interact with the code running inside the TEE. This is great to protect against malicious actors, but it also restricts the honest actors. It has to be expected that debugging and handling of emergencies will become much more difficult compared to running an MPC node outside of a TEE.

This is a good moment to remind the reader that threshold crypotgrapy requires `threshold` operational nodes. - anything less than that, and the protocol finds itself incapacitated, not able to move any funds.

Therefore, Near-One will roll-out their TEE implementation in two phases:
- Soft Launch: All mainnet nodes are running within TEEs. Their key shares are backed-up outside of the TEE.
- Hard Launch: All mainnet nodes are running within TEEs. Their key shares are backed-up inside a different TEE.

In order to protect the network from the worst case scenario (complete loss of funds due to loss of key shares or an incapacitated network), a disaster recovery plan is prepared.


## Disaster Recovery
Distaster recovery is a plan intended to prevent a permanent loss of the signing quorum.
As long as the secret shares of the MPC nodes are securely backed-up outside of the TEE environment in which the node is running, it highly likely that the network will be able to recover from otherwise catastrophic events.

Therefore, the disaster recovery plan aims at establishing a secure mechanism allowing to back-up the secret shares held by the nodes. It encompasses two steps:
1. (Back-up Generation): export the private keys from the TEE in a secure manner.
2. (Recovery): when required, securely import the private keys into the node.

### Back-up mechanism:
On a high-level, the back-up mechanism works like this:

1. The node running inside the TEE and the back-up recipient must agree on a key used to encrypt the secrets.
2. The node encrypts the sensitive secret shares with the derived key.
3. The node exports the encrypted secret shares.

#### Agreeing on an encryption key
A pair-wise key establishement scheme can be leveraged to establish a symmetric key. A suitable implementation can be found in [libsodium](https://doc.libsodium.org/) and its rust wrapper [libsodium-rs](https://docs.rs/crate/libsodium-rs/latest). Specifically, the **key exchange protocol based on X25519** would be a good fit for the given set-up (c.f. [libsodium](https://doc.libsodium.org/key_exchange) and [libsodium-rs](https://docs.rs/libsodium-rs/latest/libsodium_rs/crypto_kx/index.html)).

_Note: This key exchange protocol is on Curve25519, which is different from the Edwards curve used by NEAR._

The key establishment scheme requires that the node as well as the back-up recipient have *mutually authenticated Curve25519 public keys*. The NEAR blockchain can be leveraged for this, more specifically:
- the node operator whitelists a NEAR-account associated to the back-up recipient in the MPC smart contract.
- the back-up recipient submits a public key (Curve25519) to the MPC smart contract. The smart contract only accepts it if the account has been whitelisted by the node operator.
- the node submits a public key (Curve25519) to the MPC smart contract. The smart contract only accepts it if the public key submitting this transaction is an access key of the node operators account.

_Note: Curve25519 and edwards25519 are [birationally equivalent](https://crypto.stackexchange.com/questions/43013/what-does-birational-equivalence-mean-in-a-cryptographic-context), so one could theoretically use NEAR account keys. But it seems cleaner if we just have the node and the back-up recipient generate dedicated keys for this._

#### Encrypting the secret
The node running inside the TEE monitors the contract and can derive an encryption key using its secret key and the public key submitted by the back-up recipient.

#### Exporting the encrypted secret
The back-up service triggers the export of the back-up through a call to the smart contract or a dedicated web-endpoint.
The node returns the encrypted key either:
- as a response to a request to its web-endpoint;
- by printing its hex-value to the logs;
- or through some other mechanism (@Barak, are there alternatives?)

The back-up mechanism can then decrypt the received ciphertext to verify the received shares, before storing the encrypted shares in a secure database.

### Restoration Mechanism:
#### Encryption Key Agreement & Encrypting the secret 
Same as above, just reversed roles.

#### Importing the encrypted secret into the node
The back-up service (triggered by the node operator or a smart-contract state change), posts the data to an endpoint of the node.

### Notes:
- keep the web-endpoint private. Should we use a new webserver for that, on a different port?
- instead of relying on web-endpoints, could we use TLS keys & connect via network, or connect via unix sockets?
- for the hard-launch, the back-up service will need to run inside a TEE and must pass attestation verification on the contract.


## Materials:
https://nearone.slack.com/archives/C07UW93JVQ8/p1753830474083739
NIST SP 800-56A https://csrc.nist.gov/pubs/sp/800/56/a/r3/final
https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar3.pdf - page 105 - 106

