# MPC Contract

This folder contains the code for the **MPC Contract**, which is deployed on the NEAR blockchain.
The contract handles signature requests submitted by users and signature responses submitted by participants of the MPC network.
Besides handling signature requests and responses, this contract allows participants to join or leave the mpc network, to initiate key resharings or to propose and vote on updates to this contract.

## Contract Version
The currently deployed version of the contract is `V0`, with `V1` expected to be deployed in Q1 of 2025. Contract `V1` will introduce several efficiency improvements:

- **Lower gas costs**: Signature requests in `V1` will consume approximately half the gas compared to `V0`, mainly due to optimizations in state handling and reducing the number of receipts required per request.
- **Removal of the signature request limit**: `V0` imposed a hard limit on the number of signature requests, which `V1` removes. This limit was necessary for [previous MPC nodes](https://github.com/near/mpc/releases/tag/1.0.0-rc.5), but is no longer required due to performance improvements by the [current release](https://github.com/Near-One/mpc/releases/tag/testnet-upgrade) (currently on testnet). 

### Congestion Considerations for `V1`

Assuming:
- 300 signature requests per second,
- A block time of over 1 second, and
- An estimated signature request cost of ~6 TGas,

The **chunk size limit of 1000 TGas** is expected to provide a natural cap on the number of pending requests, ensuring that the mpc-nodes will not be overwhelmed.
In case any of above assumptions change or fail, a hard limit might need to be re-introduced in a future version of the contract.

### Migration Considerations

Migration from `V0` to `V1` will not affect how users interact with the contract.

### Benchmarks
For 40 signatures:
| Contract  | avg. receipts | avg. gas [Tgas] |
| ------------- | ------------- | ------------- |
| V0  | 8  |11.30479597562405|
| V1  | 4  |6.131075775468398 |

### Signature Request
Each row is a promise, ignore empty rows.

| V0  | V1 |
| ------------- | ------------- |
 do some checks | do some checks, add request to state, schedule yield promise
add request to state, schedule yield promise | 
 remove signature request from state | clean state & return signature or error 
 return signature or error | 

## `V1` Contract API
The following functions are public.

### User API
- `remove_timed_out_requests()`:
Removes expired signature requests from the contract.
- `sign(request: SignRequest)`:
Submits a signature request, validating the request and ensuring necessary fees and gas are provided.
- `public_key()`:
Returns the aggregated public key used by all participants in the network.
- `derived_public_key(path: String, predecessor: Option<AccountId>)`:
Generates a derived public key for a given path and account.
- `latest_key_version()`:
Returns the latest supported key version.
- `experimental_signature_deposit()`:
Calculates the required deposit fee for submitting a signature request, adjusting dynamically based on network load.


### Participants API

The following functions require that the signer is a participant.

- `respond(request: SignatureRequest, response: SignatureResponse) -> Result<(), Error>`:
Processes a response to a signature request, verifying its validity and ensuring proper state cleanup.
- `join(url: String, cipher_pk: primitives::hpke::PublicKey, sign_pk: PublicKey) -> Result<(), Error>`:
Allows a node to join the network by submitting necessary public keys and a URL.
- `vote_join(candidate: AccountId) -> Result<bool, Error>`:
Votes to accept a candidate node into the network. If the threshold is met, the candidate is added as a participant.
- `vote_leave(kick: AccountId) -> Result<bool, Error>`:
Votes to remove a participant from the network. If the threshold is met, the participant is removed.
- `vote_pk(public_key: PublicKey) -> Result<bool, Error>`:
Votes to establish a new public key for the network.
- `vote_reshared(epoch: u64) -> Result<bool, Error>`:
Votes to complete the key resharing process for a new epoch.
- `propose_update(args: ProposeUpdateArgs) -> Result<UpdateId, Error>`:
Proposes an update to the contract, requiring an attached deposit.
- `vote_update(id: UpdateId) -> Result<bool, Error>`:
Votes on a proposed update. If the threshold is met, the update is executed.


### Developer API

- `init(threshold: usize, candidates: BTreeMap<AccountId, CandidateInfo>, init_config: Option<InitConfigV1>) -> Result<Self, Error>`:
Initializes the contract with a threshold and candidate participants. Can only be called once.
- `state() -> &ProtocolContractState`:
Returns the current state of the contract.
- `get_pending_request(request: &SignatureRequest) -> Option<YieldIndex>`:
Retrieves pending signature requests.
- `config() -> &ConfigV1`:
Returns the contract configuration.
- `version() -> String`:
Returns the contract version.
- `update_config(config: ConfigV1)`:
Updates the contract configuration for `V1`.


