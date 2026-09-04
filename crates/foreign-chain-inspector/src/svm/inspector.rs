use jsonrpsee::core::client::ClientT;
use jsonrpsee::core::client::error::Error as RpcClientError;

use crate::svm::{SvmExtractedValue, SvmTransactionSignature};
use crate::{
    ClassifyRpcOutcome, ForeignChainInspectionError, ForeignChainInspector, HexBytes, NO_PARAMS,
    NetworkFingerprint, NetworkFingerprintInspector, Verdict,
};
use foreign_chain_rpc_interfaces::svm::{
    Commitment, GetAccountInfoArgs, GetAccountInfoResponse, GetTransactionArgs,
    GetTransactionResponse, TransactionMeta,
};
use near_mpc_contract_interface::types::{SvmAccount, SvmAddress, SvmInnerInstruction};
use std::collections::BTreeMap;

const GET_TRANSACTION_METHOD: &str = "getTransaction";
const GET_ACCOUNT_INFO_METHOD: &str = "getAccountInfo";
const GET_GENESIS_HASH_METHOD: &str = "getGenesisHash";

/// `TransactionHistoryNotAvailable`: the node runs without `--enable-rpc-transaction-history`,
/// which is the default. A provider gap rather than a refusal, so it is reported as a transient
/// failure and the fan-out falls through to a provider that does serve history. The shared
/// classifier would otherwise read any unrecognized JSON-RPC code as a deterministic rejection.
const TRANSACTION_HISTORY_NOT_AVAILABLE_CODE: i32 = -32011;

/// Base58 of a 32-byte value is at most 44 characters, of a 64-byte value at most 88.
/// Inputs beyond the cap are rejected before the superlinear base58 decode runs.
const MAX_PUBKEY_BASE58_CHARS: usize = 44;
const MAX_SIGNATURE_BASE58_CHARS: usize = 88;

/// Inner-instruction data is bounded by the runtime's 10 KiB Cross-Program Invocation (CPI)
/// cap (13,985 base58 characters), not by the 1232-byte transaction packet, since it is built
/// at runtime.
const MAX_INSTRUCTION_DATA_BASE58_CHARS: usize = 14_000;

/// The runtime's cap on the accounts a CPI instruction may reference, duplicates included.
/// Enforced before the one-byte wire indices are resolved into 32-byte pubkeys.
const MAX_INSTRUCTION_ACCOUNTS: usize = 255;

/// Marker trait for SVM chain type parameters, so that different chains' inspectors stay
/// type-incompatible while sharing the single [`SvmInspector`] implementation.
pub trait SvmChain {}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Solana;

impl SvmChain for Solana {}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Fogo;

impl SvmChain for Fogo {}

pub type SolanaInspector<Client> = SvmInspector<Client, Solana>;
pub type FogoInspector<Client> = SvmInspector<Client, Fogo>;

#[derive(Clone)]
pub struct SvmInspector<Client, Chain> {
    client: Client,
    _chain: std::marker::PhantomData<Chain>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum SvmFinality {
    /// Optimistically confirmed: voted by a supermajority, but not yet rooted.
    Confirmed,
    Finalized,
}

impl From<SvmFinality> for Commitment {
    fn from(finality: SvmFinality) -> Self {
        match finality {
            SvmFinality::Confirmed => Commitment::Confirmed,
            SvmFinality::Finalized => Commitment::Finalized,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SvmExtractor {
    InnerInstruction {
        instruction_index: usize,
        inner_instruction_index: usize,
    },
    AccountState {
        pubkey: SvmAddress,
    },
}

impl<Client, Chain> ForeignChainInspector for SvmInspector<Client, Chain>
where
    Client: ClientT + Send + Sync,
    Chain: SvmChain + Send + Sync,
{
    type TransactionId = SvmTransactionSignature;
    type Finality = SvmFinality;
    type Extractor = SvmExtractor;
    type ExtractedValue = SvmExtractedValue;

    async fn extract(
        &self,
        tx_id: SvmTransactionSignature,
        finality: SvmFinality,
        extractors: Vec<SvmExtractor>,
    ) -> Result<Verdict<SvmExtractedValue>, ForeignChainInspectionError> {
        let commitment = Commitment::from(finality);
        let Some(tx) = self.fetch_transaction(tx_id, commitment).await? else {
            return Ok(Verdict::TransactionNotFound);
        };
        let meta = transaction_meta(&tx)?;
        if !meta.err.is_null() {
            return Ok(Verdict::TransactionFailed);
        }
        self.extract_values(&tx, meta, commitment, &extractors).await
    }
}

impl<Client, Chain> SvmInspector<Client, Chain>
where
    Client: ClientT + Send + Sync,
    Chain: SvmChain,
{
    pub fn new(client: Client) -> Self {
        Self {
            client,
            _chain: std::marker::PhantomData,
        }
    }

    /// The transaction as the provider serves it at `commitment`, which is the whole finality
    /// check: `finalized` is answered only from slots the serving node has rooted. Reading a
    /// root separately and comparing slots against it would instead stitch two answers
    /// together, which a load-balanced endpoint is free to serve from different backends.
    /// A `null` covers an unknown transaction and one that is confirmed but not yet rooted
    /// alike, so the second read tells the retriable [`ForeignChainInspectionError::NotFinalized`]
    /// from the settled [`Verdict::TransactionNotFound`], reported here as [`None`].
    async fn fetch_transaction(
        &self,
        tx_id: SvmTransactionSignature,
        commitment: Commitment,
    ) -> Result<Option<GetTransactionResponse>, ForeignChainInspectionError> {
        if let Some(tx) = self.request_transaction(tx_id, commitment).await? {
            return Ok(Some(tx));
        }
        if commitment == Commitment::Finalized
            && self
                .request_transaction(tx_id, Commitment::Confirmed)
                .await?
                .is_some()
        {
            return Err(ForeignChainInspectionError::NotFinalized);
        }
        Ok(None)
    }

    async fn request_transaction(
        &self,
        tx_id: SvmTransactionSignature,
        commitment: Commitment,
    ) -> Result<Option<GetTransactionResponse>, ForeignChainInspectionError> {
        let args = GetTransactionArgs {
            signature: bs58::encode(*tx_id).into_string(),
            commitment,
        };
        let outcome = self.client.request(GET_TRANSACTION_METHOD, &args).await;
        let response: Option<GetTransactionResponse> = match outcome {
            Err(RpcClientError::Call(object))
                if object.code() == TRANSACTION_HISTORY_NOT_AVAILABLE_CODE =>
            {
                return Err(ForeignChainInspectionError::RpcRequestFailed(
                    "provider does not serve transaction history".to_string(),
                ));
            }
            other => other.classified()?,
        };
        if let Some(tx) = &response {
            let returned = tx.transaction.signatures.first().map(String::as_str);
            ensure_signature_matches(&tx_id, returned)?;
        }
        Ok(response)
    }

    /// Resolves the extractors in request order. One read per distinct account: a pubkey named
    /// twice in one request would otherwise cost a round trip each and could observe two
    /// different states within a single payload.
    async fn extract_values(
        &self,
        tx: &GetTransactionResponse,
        meta: &TransactionMeta,
        commitment: Commitment,
        extractors: &[SvmExtractor],
    ) -> Result<Verdict<SvmExtractedValue>, ForeignChainInspectionError> {
        let account_keys = account_key_list(&tx.transaction.message.account_keys, meta);
        let mut accounts: BTreeMap<SvmAddress, SvmAccount> = BTreeMap::new();
        let mut extracted_values = Vec::with_capacity(extractors.len());
        for extractor in extractors {
            let value = match extractor {
                SvmExtractor::InnerInstruction {
                    instruction_index,
                    inner_instruction_index,
                } => {
                    let Some(instruction) = extract_inner_instruction(
                        meta,
                        &account_keys,
                        *instruction_index,
                        *inner_instruction_index,
                    )?
                    else {
                        return Ok(Verdict::LogIndexOutOfBounds);
                    };
                    instruction
                }
                SvmExtractor::AccountState { pubkey } => {
                    let account = match accounts.get(pubkey) {
                        Some(account) => account.clone(),
                        None => {
                            let Some(account) =
                                self.fetch_account_state(pubkey, commitment, tx.slot).await?
                            else {
                                return Ok(Verdict::AccountNotFound);
                            };
                            accounts.insert(pubkey.clone(), account.clone());
                            account
                        }
                    };
                    SvmExtractedValue::AccountState(account)
                }
            };
            extracted_values.push(value);
        }

        Ok(Verdict::Extracted(extracted_values))
    }

    async fn fetch_account_state(
        &self,
        pubkey: &SvmAddress,
        commitment: Commitment,
        tx_slot: u64,
    ) -> Result<Option<SvmAccount>, ForeignChainInspectionError> {
        let args = GetAccountInfoArgs {
            pubkey: bs58::encode(pubkey.0).into_string(),
            commitment,
        };
        let response: GetAccountInfoResponse = self
            .client
            .request(GET_ACCOUNT_INFO_METHOD, &args)
            .await
            .classified()?;
        // A load-balanced endpoint can route this read to a backend that has not seen the
        // transaction, whose pre-transaction answer would otherwise be taken as a verdict.
        // An error, so that backend drops out rather than settling the request.
        if response.context.slot < tx_slot {
            return Err(ForeignChainInspectionError::RpcRequestFailed(format!(
                "account read answered at slot {}, before the transaction's slot {tx_slot}",
                response.context.slot
            )));
        }
        // No account at the address is the `AccountNotFound` verdict, reported as `None`.
        let Some(account) = response.value else {
            return Ok(None);
        };

        let owner = parse_svm_pubkey(&account.owner).map_err(|reason| {
            ForeignChainInspectionError::MalformedRpcResponse(format!(
                "failed to parse account owner: {reason}"
            ))
        })?;
        let data = account
            .data
            .decode()
            .map_err(ForeignChainInspectionError::MalformedRpcResponse)?;

        Ok(Some(SvmAccount { owner, data }))
    }
}

impl<Client, Chain> NetworkFingerprintInspector for SvmInspector<Client, Chain>
where
    Client: ClientT + Send + Sync,
    Chain: Send + Sync,
{
    async fn network_fingerprint(&self) -> Result<NetworkFingerprint, ForeignChainInspectionError> {
        let genesis_hash: String = self
            .client
            .request(GET_GENESIS_HASH_METHOD, NO_PARAMS)
            .await
            .classified()?;
        Ok(self.canonical_fingerprint(&genesis_hash))
    }

    fn canonical_fingerprint(&self, fingerprint: &str) -> NetworkFingerprint {
        canonical_genesis_hash(fingerprint)
    }
}

/// Trims surrounding whitespace; base58 admits no other spelling of the same 32 bytes. Text
/// that is not a 32-byte base58 value is returned unchanged rather than rejected, so that the
/// mismatch an operator is shown carries what the provider actually answered.
fn canonical_genesis_hash(fingerprint: &str) -> NetworkFingerprint {
    let canonical = decode_base58_32(fingerprint.trim())
        .map(|bytes| bs58::encode(bytes).into_string())
        .unwrap_or_else(|_| fingerprint.to_owned());
    NetworkFingerprint::new(canonical)
}

/// A node that holds the transaction but not its status metadata is a provider gap, not corrupt
/// data — the same class as an absent inner-instruction list, and reported the same way, so the
/// fan-out falls through to a provider that does serve it. Without `meta` there is no `err`
/// either, so a success cannot be told from a failure.
fn transaction_meta(
    tx: &GetTransactionResponse,
) -> Result<&TransactionMeta, ForeignChainInspectionError> {
    tx.meta.as_ref().ok_or_else(|| {
        ForeignChainInspectionError::RpcRequestFailed(
            "provider does not serve the transaction's status metadata".to_string(),
        )
    })
}

/// Rejects a backend that returned a different transaction than queried. The transaction
/// id is the first signature; a missing or undecodable one is a malformed response, a
/// well-formed but different one is a hard inconsistency.
fn ensure_signature_matches(
    requested: &[u8; 64],
    returned: Option<&str>,
) -> Result<(), ForeignChainInspectionError> {
    let returned = returned.ok_or_else(|| {
        ForeignChainInspectionError::MalformedRpcResponse(
            "transaction has no signatures".to_string(),
        )
    })?;
    if returned.len() > MAX_SIGNATURE_BASE58_CHARS {
        return Err(ForeignChainInspectionError::MalformedRpcResponse(
            "transaction signature exceeds the base58 length of 64 bytes".to_string(),
        ));
    }
    let decoded = bs58::decode(returned).into_vec().map_err(|e| {
        ForeignChainInspectionError::MalformedRpcResponse(format!(
            "invalid transaction signature in response: {e}"
        ))
    })?;
    if decoded != requested {
        return Err(ForeignChainInspectionError::InconsistentRpcResponse {
            requested_hash: HexBytes(requested.to_vec()),
            returned_hash: HexBytes(decoded),
        });
    }
    Ok(())
}

/// The transaction's full account list: static account keys, then the addresses loaded
/// from lookup tables, writable before readonly — the order instruction indices are
/// defined against. Left undecoded so a malformed key nothing reads cannot fail the
/// request with a non-transient error.
fn account_key_list<'a>(static_keys: &'a [String], meta: &'a TransactionMeta) -> Vec<&'a str> {
    let loaded = meta.loaded_addresses.as_ref();
    let loaded_writable = loaded.map(|l| l.writable.as_slice()).unwrap_or_default();
    let loaded_readonly = loaded.map(|l| l.readonly.as_slice()).unwrap_or_default();

    static_keys
        .iter()
        .chain(loaded_writable)
        .chain(loaded_readonly)
        .map(String::as_str)
        .collect()
}

fn extract_inner_instruction(
    meta: &TransactionMeta,
    account_keys: &[&str],
    instruction_index: usize,
    inner_instruction_index: usize,
) -> Result<Option<SvmExtractedValue>, ForeignChainInspectionError> {
    // An absent list means the node does not record inner instructions — a provider gap, so the
    // fan-out falls through to a provider that does record them. An empty list, by contrast, is
    // the chain's own answer, and an index into it is the `LogIndexOutOfBounds` verdict.
    let entries = meta.inner_instructions.as_deref().ok_or_else(|| {
        ForeignChainInspectionError::RpcRequestFailed(
            "provider does not record inner instructions".to_string(),
        )
    })?;
    let instruction = entries
        .iter()
        .find(|entry| usize::from(entry.index) == instruction_index)
        .and_then(|entry| entry.instructions.get(inner_instruction_index));
    let Some(instruction) = instruction else {
        return Ok(None);
    };

    let resolve = |index: u8, role: &str| {
        let key = account_keys.get(usize::from(index)).ok_or_else(|| {
            ForeignChainInspectionError::MalformedRpcResponse(format!(
                "instruction {role} index {index} is out of bounds ({} account keys)",
                account_keys.len()
            ))
        })?;
        parse_svm_pubkey(key).map_err(|reason| {
            ForeignChainInspectionError::MalformedRpcResponse(format!(
                "failed to parse account key: {reason}"
            ))
        })
    };

    let program_id = resolve(instruction.program_id_index, "program id")?;
    if instruction.accounts.len() > MAX_INSTRUCTION_ACCOUNTS {
        return Err(ForeignChainInspectionError::MalformedRpcResponse(format!(
            "instruction lists {} accounts, more than an instruction can carry",
            instruction.accounts.len()
        )));
    }
    let accounts = instruction
        .accounts
        .iter()
        .map(|&index| resolve(index, "account"))
        .collect::<Result<Vec<_>, _>>()?;

    if instruction.data.len() > MAX_INSTRUCTION_DATA_BASE58_CHARS {
        return Err(ForeignChainInspectionError::MalformedRpcResponse(
            "instruction data exceeds the size an inner instruction can carry".to_string(),
        ));
    }
    let data = bs58::decode(&instruction.data).into_vec().map_err(|e| {
        ForeignChainInspectionError::MalformedRpcResponse(format!(
            "invalid base58 instruction data: {e}"
        ))
    })?;

    Ok(Some(SvmExtractedValue::InnerInstruction(
        SvmInnerInstruction {
            program_id,
            accounts,
            data,
        },
    )))
}

/// Parse a base58 SVM pubkey into [`SvmAddress`]; exactly 32 bytes, no short spellings.
fn parse_svm_pubkey(s: &str) -> Result<SvmAddress, String> {
    decode_base58_32(s).map(SvmAddress)
}

fn decode_base58_32(s: &str) -> Result<[u8; 32], String> {
    if s.len() > MAX_PUBKEY_BASE58_CHARS {
        return Err(format!(
            "base58 string of {} characters is too long for 32 bytes",
            s.len()
        ));
    }
    let decoded = bs58::decode(s)
        .into_vec()
        .map_err(|e| format!("invalid base58 {s:?}: {e}"))?;
    <[u8; 32]>::try_from(decoded)
        .map_err(|decoded| format!("expected 32 bytes, got {} in {s:?}", decoded.len()))
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use assert_matches::assert_matches;
    use rstest::rstest;

    const SYSTEM_PROGRAM_BASE58: &str = "11111111111111111111111111111111";

    #[test]
    fn ensure_signature_matches__should_accept_matching_signature() {
        // Given
        let signature = [0xab; 64];
        let encoded = bs58::encode(signature).into_string();

        // When / Then
        ensure_signature_matches(&signature, Some(&encoded)).unwrap();
    }

    #[test]
    fn ensure_signature_matches__should_reject_different_signature() {
        // Given
        let encoded_other = bs58::encode([0xcd; 64]).into_string();

        // When / Then
        assert_matches!(
            ensure_signature_matches(&[0xab; 64], Some(&encoded_other)),
            Err(ForeignChainInspectionError::InconsistentRpcResponse { .. })
        );
    }

    #[test]
    fn ensure_signature_matches__should_reject_missing_signature_as_malformed() {
        // When / Then
        assert_matches!(
            ensure_signature_matches(&[0xab; 64], None),
            Err(ForeignChainInspectionError::MalformedRpcResponse(_))
        );
    }

    #[test]
    fn ensure_signature_matches__should_reject_non_base58_signature_as_malformed() {
        // Given — 0, O, I and l are not part of the base58 alphabet.
        // When / Then
        assert_matches!(
            ensure_signature_matches(&[0xab; 64], Some("not-base58-0OIl")),
            Err(ForeignChainInspectionError::MalformedRpcResponse(_))
        );
    }

    #[test]
    fn ensure_signature_matches__should_reject_oversized_signature_without_decoding() {
        // Given — a base58 string far longer than any 64-byte signature. Decoding it
        // with `bs58` is superlinear, so it must be rejected on length before the
        // decode runs.
        let oversized = "1".repeat(1_000_000);

        // When / Then
        assert_matches!(
            ensure_signature_matches(&[0xab; 64], Some(&oversized)),
            Err(ForeignChainInspectionError::MalformedRpcResponse(_))
        );
    }

    #[test]
    fn ensure_signature_matches__should_reject_shorter_signature_as_inconsistent() {
        // Given — decodes fine but to 63 bytes, which simply differs from the
        // requested 64.
        let short = bs58::encode([0xab; 63]).into_string();

        // When / Then
        assert_matches!(
            ensure_signature_matches(&[0xab; 64], Some(&short)),
            Err(ForeignChainInspectionError::InconsistentRpcResponse { .. })
        );
    }

    #[test]
    fn parse_svm_pubkey__should_accept_the_system_program_id() {
        // Given — the all-zero pubkey, whose base58 spelling is 32 ones.
        // When
        let address = parse_svm_pubkey(SYSTEM_PROGRAM_BASE58).unwrap();

        // Then
        assert_eq!(address.0, [0u8; 32]);
    }

    #[test]
    fn parse_svm_pubkey__should_roundtrip_a_full_range_pubkey() {
        // Given
        let bytes: [u8; 32] = core::array::from_fn(|i| i as u8);
        let encoded = bs58::encode(bytes).into_string();

        // When
        let address = parse_svm_pubkey(&encoded).unwrap();

        // Then
        assert_eq!(address.0, bytes);
    }

    #[rstest]
    #[case::empty("")]
    #[case::too_short_decoding(&bs58::encode([0xab; 31]).into_string())]
    #[case::too_long_decoding(&bs58::encode([0xab; 33]).into_string())]
    #[case::not_base58("0OIl")]
    #[case::oversized(&"1".repeat(1_000_000))]
    fn parse_svm_pubkey__should_reject_strings_that_are_not_32_base58_bytes(#[case] input: &str) {
        parse_svm_pubkey(input).unwrap_err();
    }

    #[rstest]
    #[case::valid_is_reencoded(
        "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d",
        "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d"
    )]
    #[case::whitespace_is_trimmed(
        " 5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d\n",
        "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d"
    )]
    #[case::unparseable_is_returned_unchanged("not-a-genesis-hash", "not-a-genesis-hash")]
    fn canonical_genesis_hash__should_canonicalize_what_a_provider_answers(
        #[case] answered: &str,
        #[case] expected: &str,
    ) {
        // When
        let fingerprint = canonical_genesis_hash(answered);

        // Then
        assert_eq!(fingerprint.to_string(), expected);
    }
}
