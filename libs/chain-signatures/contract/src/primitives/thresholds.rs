use super::participants::{ParticipantId, ParticipantInfo, Participants};
use crate::{
    errors::{Error, InvalidCandidateSet, InvalidThreshold},
    TeeParticipantInfo,
};
use near_sdk::{near, AccountId};
use std::collections::BTreeMap;

/// Minimum absolute threshold required.
const MIN_THRESHOLD_ABSOLUTE: u64 = 2;

/// Stores the cryptographic threshold for a distributed key.
/// ```
/// use mpc_contract::primitives::thresholds::Threshold;
/// let dt = Threshold::new(8);
/// assert!(dt.value() == 8);
/// ```
#[near(serializers=[borsh, json])]
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct Threshold(u64);
impl Threshold {
    pub fn new(val: u64) -> Self {
        Threshold(val)
    }
    pub fn value(&self) -> u64 {
        self.0
    }
}

/// Stores information about the threshold key parameters:
/// - owners of key shares
/// - cryptographic threshold
#[near(serializers=[borsh, json])]
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct ThresholdParameters {
    participants: Participants,
    threshold: Threshold,
    tee_participant_info: TeeParticipantInfo,
}

impl ThresholdParameters {
    /// Constructs Threshold parameters from `participants` and `threshold` if the
    /// threshold meets the absolute and relative validation criteria.
    pub fn new(
        participants: Participants,
        threshold: Threshold,
        tee_participant_info: TeeParticipantInfo,
    ) -> Result<Self, Error> {
        match Self::validate_threshold(participants.len() as u64, threshold.clone()) {
            Ok(_) => Ok(ThresholdParameters {
                participants,
                threshold,
                tee_participant_info,
            }),
            Err(err) => Err(err),
        }
    }

    /// Ensures that the threshold `k` is sensible and meets the absolute and minimum requirements.
    /// That is:
    /// - threshold must be at least `MIN_THRESHOLD_ABSOLUTE`
    /// - threshold can not exceed the number of shares `n_shares`.
    /// - threshold must be at least 60% of the number of shares (rounded upwards).
    pub fn validate_threshold(n_shares: u64, k: Threshold) -> Result<(), Error> {
        if k.value() > n_shares {
            return Err(InvalidThreshold::MaxRequirementFailed
                .message(format!("cannot exceed {}, found {:?}", n_shares, k)));
        }
        if k.value() < MIN_THRESHOLD_ABSOLUTE {
            return Err(InvalidThreshold::MinAbsRequirementFailed.into());
        }
        let percentage_bound = (3 * n_shares + 4) / 5; // minimum 60%
        if k.value() < percentage_bound {
            return Err(InvalidThreshold::MinRelRequirementFailed.message(format!(
                "require at least {}, found {:?}",
                percentage_bound, k
            )));
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), Error> {
        Self::validate_threshold(self.participants.len() as u64, self.threshold())?;
        self.participants.validate()?;
        self.tee_participant_info
            .verify_quote(near_sdk::env::block_timestamp_ms() / 1_000)
            .map_err(|_| Error::from(InvalidCandidateSet::InvalidParticipantsTeeQuote))?;
        Ok(())
    }

    /// Validates the incoming proposal against the current one, ensuring it's allowed based on the
    /// current participants and threshold settings. Also verifies the TEE quote of the participant
    /// who submitted the proposal.
    pub fn validate_incoming_proposal(&self, proposal: &ThresholdParameters) -> Result<(), Error> {
        // ensure the proposed threshold parameters are valid:
        // if performance issue, inline and merge with loop below
        proposal.validate()?;
        let mut old_by_id: BTreeMap<ParticipantId, AccountId> = BTreeMap::new();
        let mut old_by_acc: BTreeMap<AccountId, (ParticipantId, ParticipantInfo)> = BTreeMap::new();
        for (acc, id, info) in self.participants().participants() {
            old_by_id.insert(id.clone(), acc.clone());
            old_by_acc.insert(acc.clone(), (id.clone(), info.clone()));
        }
        let new_participants = proposal.participants().participants();
        let mut new_min_id = u32::MAX;
        let mut new_max_id = 0u32;
        let mut n_old = 0u64;
        for (new_account, new_id, new_info) in new_participants {
            match old_by_acc.get(new_account) {
                Some((old_id, old_info)) => {
                    if new_id != old_id {
                        return Err(InvalidCandidateSet::IncoherentParticipantIds.into());
                    }
                    if *new_info != *old_info {
                        return Err(InvalidCandidateSet::IncoherentParticipantIds.into());
                    }
                    n_old += 1;
                }
                None => {
                    if old_by_id.contains_key(new_id) {
                        return Err(InvalidCandidateSet::IncoherentParticipantIds.into());
                    }
                    new_min_id = std::cmp::min(new_min_id, new_id.get());
                    new_max_id = std::cmp::max(new_max_id, new_id.get());
                }
            }
        }
        // assert there are enough old participants
        if n_old < self.threshold().value() {
            return Err(InvalidCandidateSet::InsufficientOldParticipants.into());
        }
        // ensure the new ids are contiguous and unique
        let n_new = proposal.participants().len() as u64 - n_old;
        if n_new > 0 {
            if n_new - 1 != (new_max_id - new_min_id) as u64 {
                return Err(InvalidCandidateSet::NewParticipantIdsNotContiguous.into());
            }
            if new_min_id != self.participants().next_id().get() {
                return Err(InvalidCandidateSet::NewParticipantIdsNotContiguous.into());
            }
            if new_max_id + 1 != proposal.participants().next_id().get() {
                return Err(InvalidCandidateSet::NewParticipantIdsTooHigh.into());
            }
        }
        Ok(())
    }

    pub fn threshold(&self) -> Threshold {
        self.threshold.clone()
    }
    /// Returns the map of Participants.
    pub fn participants(&self) -> &Participants {
        &self.participants
    }

    /// For integration testing.
    pub fn new_unvalidated(participants: Participants, threshold: Threshold) -> Self {
        let quote_collateral = serde_json::json!({"tcb_info_issuer_chain":"-----BEGIN CERTIFICATE-----\nMIICizCCAjKgAwIBAgIUfjiC1ftVKUpASY5FhAPpFJG99FUwCgYIKoZIzj0EAwIw\naDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENv\ncnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJ\nBgNVBAYTAlVTMB4XDTE4MDUyMTEwNTAxMFoXDTI1MDUyMTEwNTAxMFowbDEeMBwG\nA1UEAwwVSW50ZWwgU0dYIFRDQiBTaWduaW5nMRowGAYDVQQKDBFJbnRlbCBDb3Jw\nb3JhdGlvbjEUMBIGA1UEBwwLU2FudGEgQ2xhcmExCzAJBgNVBAgMAkNBMQswCQYD\nVQQGEwJVUzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABENFG8xzydWRfK92bmGv\nP+mAh91PEyV7Jh6FGJd5ndE9aBH7R3E4A7ubrlh/zN3C4xvpoouGlirMba+W2lju\nypajgbUwgbIwHwYDVR0jBBgwFoAUImUM1lqdNInzg7SVUr9QGzknBqwwUgYDVR0f\nBEswSTBHoEWgQ4ZBaHR0cHM6Ly9jZXJ0aWZpY2F0ZXMudHJ1c3RlZHNlcnZpY2Vz\nLmludGVsLmNvbS9JbnRlbFNHWFJvb3RDQS5kZXIwHQYDVR0OBBYEFH44gtX7VSlK\nQEmORYQD6RSRvfRVMA4GA1UdDwEB/wQEAwIGwDAMBgNVHRMBAf8EAjAAMAoGCCqG\nSM49BAMCA0cAMEQCIB9C8wOAN/ImxDtGACV246KcqjagZOR0kyctyBrsGGJVAiAj\nftbrNGsGU8YH211dRiYNoPPu19Zp/ze8JmhujB0oBw==\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIICjzCCAjSgAwIBAgIUImUM1lqdNInzg7SVUr9QGzknBqwwCgYIKoZIzj0EAwIw\naDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENv\ncnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJ\nBgNVBAYTAlVTMB4XDTE4MDUyMTEwNDUxMFoXDTQ5MTIzMTIzNTk1OVowaDEaMBgG\nA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0\naW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJBgNVBAYT\nAlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEC6nEwMDIYZOj/iPWsCzaEKi7\n1OiOSLRFhWGjbnBVJfVnkY4u3IjkDYYL0MxO4mqsyYjlBalTVYxFP2sJBK5zlKOB\nuzCBuDAfBgNVHSMEGDAWgBQiZQzWWp00ifODtJVSv1AbOScGrDBSBgNVHR8ESzBJ\nMEegRaBDhkFodHRwczovL2NlcnRpZmljYXRlcy50cnVzdGVkc2VydmljZXMuaW50\nZWwuY29tL0ludGVsU0dYUm9vdENBLmRlcjAdBgNVHQ4EFgQUImUM1lqdNInzg7SV\nUr9QGzknBqwwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEwCgYI\nKoZIzj0EAwIDSQAwRgIhAOW/5QkR+S9CiSDcNoowLuPRLsWGf/Yi7GSX94BgwTwg\nAiEA4J0lrHoMs+Xo5o/sX6O9QWxHRAvZUGOdRQ7cvqRXaqI=\n-----END CERTIFICATE-----\n","tcb_info":"{\"id\":\"TDX\",\"version\":3,\"issueDate\":\"2025-03-11T00:36:15Z\",\"nextUpdate\":\"2025-04-10T00:36:15Z\",\"fmspc\":\"20a06f000000\",\"pceId\":\"0000\",\"tcbType\":0,\"tcbEvaluationDataNumber\":17,\"tdxModule\":{\"mrsigner\":\"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\",\"attributes\":\"0000000000000000\",\"attributesMask\":\"FFFFFFFFFFFFFFFF\"},\"tdxModuleIdentities\":[{\"id\":\"TDX_03\",\"mrsigner\":\"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\",\"attributes\":\"0000000000000000\",\"attributesMask\":\"FFFFFFFFFFFFFFFF\",\"tcbLevels\":[{\"tcb\":{\"isvsvn\":3},\"tcbDate\":\"2024-03-13T00:00:00Z\",\"tcbStatus\":\"UpToDate\"}]},{\"id\":\"TDX_01\",\"mrsigner\":\"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\",\"attributes\":\"0000000000000000\",\"attributesMask\":\"FFFFFFFFFFFFFFFF\",\"tcbLevels\":[{\"tcb\":{\"isvsvn\":4},\"tcbDate\":\"2024-03-13T00:00:00Z\",\"tcbStatus\":\"UpToDate\"},{\"tcb\":{\"isvsvn\":2},\"tcbDate\":\"2023-08-09T00:00:00Z\",\"tcbStatus\":\"OutOfDate\"}]}],\"tcbLevels\":[{\"tcb\":{\"sgxtcbcomponents\":[{\"svn\":2,\"category\":\"BIOS\",\"type\":\"Early Microcode Update\"},{\"svn\":2,\"category\":\"OS/VMM\",\"type\":\"SGX Late Microcode Update\"},{\"svn\":2,\"category\":\"OS/VMM\",\"type\":\"TXT SINIT\"},{\"svn\":2,\"category\":\"BIOS\"},{\"svn\":2,\"category\":\"BIOS\"},{\"svn\":255,\"category\":\"BIOS\"},{\"svn\":0},{\"svn\":2,\"category\":\"OS/VMM\",\"type\":\"SEAMLDR ACM\"},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0}],\"pcesvn\":13,\"tdxtcbcomponents\":[{\"svn\":5,\"category\":\"OS/VMM\",\"type\":\"TDX Module\"},{\"svn\":0,\"category\":\"OS/VMM\",\"type\":\"TDX Module\"},{\"svn\":2,\"category\":\"OS/VMM\",\"type\":\"TDX Late Microcode Update\"},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0}]},\"tcbDate\":\"2024-03-13T00:00:00Z\",\"tcbStatus\":\"UpToDate\"},{\"tcb\":{\"sgxtcbcomponents\":[{\"svn\":2,\"category\":\"BIOS\",\"type\":\"Early Microcode Update\"},{\"svn\":2,\"category\":\"OS/VMM\",\"type\":\"SGX Late Microcode Update\"},{\"svn\":2,\"category\":\"OS/VMM\",\"type\":\"TXT SINIT\"},{\"svn\":2,\"category\":\"BIOS\"},{\"svn\":2,\"category\":\"BIOS\"},{\"svn\":255,\"category\":\"BIOS\"},{\"svn\":0},{\"svn\":2,\"category\":\"OS/VMM\",\"type\":\"SEAMLDR ACM\"},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0}],\"pcesvn\":5,\"tdxtcbcomponents\":[{\"svn\":5,\"category\":\"OS/VMM\",\"type\":\"TDX Module\"},{\"svn\":0,\"category\":\"OS/VMM\",\"type\":\"TDX Module\"},{\"svn\":2,\"category\":\"OS/VMM\",\"type\":\"TDX Late Microcode Update\"},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0},{\"svn\":0}]},\"tcbDate\":\"2018-01-04T00:00:00Z\",\"tcbStatus\":\"OutOfDate\"}]}","tcb_info_signature":"dff1380a12d533bff4ad7f69fd0355ad97ff034b42c8269e26e40e3d585dffff3e55bf21f8cda481d3c163fafcd4eab11c8818ba6aa7553ba6866bce06b56a95","qe_identity_issuer_chain":"-----BEGIN CERTIFICATE-----\nMIICizCCAjKgAwIBAgIUfjiC1ftVKUpASY5FhAPpFJG99FUwCgYIKoZIzj0EAwIw\naDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENv\ncnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJ\nBgNVBAYTAlVTMB4XDTE4MDUyMTEwNTAxMFoXDTI1MDUyMTEwNTAxMFowbDEeMBwG\nA1UEAwwVSW50ZWwgU0dYIFRDQiBTaWduaW5nMRowGAYDVQQKDBFJbnRlbCBDb3Jw\nb3JhdGlvbjEUMBIGA1UEBwwLU2FudGEgQ2xhcmExCzAJBgNVBAgMAkNBMQswCQYD\nVQQGEwJVUzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABENFG8xzydWRfK92bmGv\nP+mAh91PEyV7Jh6FGJd5ndE9aBH7R3E4A7ubrlh/zN3C4xvpoouGlirMba+W2lju\nypajgbUwgbIwHwYDVR0jBBgwFoAUImUM1lqdNInzg7SVUr9QGzknBqwwUgYDVR0f\nBEswSTBHoEWgQ4ZBaHR0cHM6Ly9jZXJ0aWZpY2F0ZXMudHJ1c3RlZHNlcnZpY2Vz\nLmludGVsLmNvbS9JbnRlbFNHWFJvb3RDQS5kZXIwHQYDVR0OBBYEFH44gtX7VSlK\nQEmORYQD6RSRvfRVMA4GA1UdDwEB/wQEAwIGwDAMBgNVHRMBAf8EAjAAMAoGCCqG\nSM49BAMCA0cAMEQCIB9C8wOAN/ImxDtGACV246KcqjagZOR0kyctyBrsGGJVAiAj\nftbrNGsGU8YH211dRiYNoPPu19Zp/ze8JmhujB0oBw==\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIICjzCCAjSgAwIBAgIUImUM1lqdNInzg7SVUr9QGzknBqwwCgYIKoZIzj0EAwIw\naDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENv\ncnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJ\nBgNVBAYTAlVTMB4XDTE4MDUyMTEwNDUxMFoXDTQ5MTIzMTIzNTk1OVowaDEaMBgG\nA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0\naW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJBgNVBAYT\nAlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEC6nEwMDIYZOj/iPWsCzaEKi7\n1OiOSLRFhWGjbnBVJfVnkY4u3IjkDYYL0MxO4mqsyYjlBalTVYxFP2sJBK5zlKOB\nuzCBuDAfBgNVHSMEGDAWgBQiZQzWWp00ifODtJVSv1AbOScGrDBSBgNVHR8ESzBJ\nMEegRaBDhkFodHRwczovL2NlcnRpZmljYXRlcy50cnVzdGVkc2VydmljZXMuaW50\nZWwuY29tL0ludGVsU0dYUm9vdENBLmRlcjAdBgNVHQ4EFgQUImUM1lqdNInzg7SV\nUr9QGzknBqwwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEwCgYI\nKoZIzj0EAwIDSQAwRgIhAOW/5QkR+S9CiSDcNoowLuPRLsWGf/Yi7GSX94BgwTwg\nAiEA4J0lrHoMs+Xo5o/sX6O9QWxHRAvZUGOdRQ7cvqRXaqI=\n-----END CERTIFICATE-----\n","qe_identity":"{\"id\":\"TD_QE\",\"version\":2,\"issueDate\":\"2025-03-10T23:38:16Z\",\"nextUpdate\":\"2025-04-09T23:38:16Z\",\"tcbEvaluationDataNumber\":17,\"miscselect\":\"00000000\",\"miscselectMask\":\"FFFFFFFF\",\"attributes\":\"11000000000000000000000000000000\",\"attributesMask\":\"FBFFFFFFFFFFFFFF0000000000000000\",\"mrsigner\":\"DC9E2A7C6F948F17474E34A7FC43ED030F7C1563F1BABDDF6340C82E0E54A8C5\",\"isvprodid\":2,\"tcbLevels\":[{\"tcb\":{\"isvsvn\":4},\"tcbDate\":\"2024-03-13T00:00:00Z\",\"tcbStatus\":\"UpToDate\"}]}","qe_identity_signature":"920d5f18df6da142a667caf71844d45dfd4de3e3b14f846bae92a3e52a9c765d855b9a8b4b54307dd3feae30f28f09888a3200c29584d7c50d42f85275afe6cc"});
        let quote_collateral = quote_collateral.to_string();
        let tee_quote = "040002008100000000000000939a7233f79c4ca9940a0db3957f0607ac666ed993e70e31ff5f5a8a2c743b220000000007010300000000000000000000000000c51e5cb16c461fe29b60394984755325ecd05a9a7a8fb3a116f1c3cf0aca4b0eb9edefb9b404deeaee4b7d454372d17a000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000702000000000000c68518a0ebb42136c12b2275164f8c72f25fa9a34392228687ed6e9caeb9c0f1dbd895e9cf475121c029dc47e70e91fd00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000085e0855a6384fa1c8a6ab36d0dcbfaa11a5753e5a070c08218ae5fe872fcb86967fd2449c29e22e59dc9fec998cb65474a7db64a609c77e85f603c23e9a9fd03bfd9e6b52ce527f774a598e66d58386026cea79b2aea13b81a0b70cfacdec0ca8a4fe048fea22663152ef128853caa5c033cbe66baf32ba1ff7f6b1afc1624c279f50a4cbc522a735ca6f69551e61ef2561c1b02351cd6f7c803dd36bc95ba25463aa025ce7761156260c9131a5d7c03aeccc10e12160ec3205bb2876a203a7fb81447910d62fd92897d68b1f51d54fb75dfe2aeba3a97a879cba59a771fc522d88046cc26b407d723f726fae17c3e5a50529d0b6c2b991d027f06a9b430d43ecc1000003bdd12b68ee3cfc93a1758479840b6f8734c2439106d8f0faa50ac919d86ea101c002c41d262670ad84afb8f9ee35c7abbb72dcc01bbc3e3a3773672d665005ee6bcb0c5f4b03f0563c797747f7ddd25d92d4f120bee4a829daca986bbc03c155b3d158f6a386bca7ee49ceb3ec31494b792e0cf22fc4e561ddc57156da1b77a0600461000000303070704ff00020000000000000000000000000000000000000000000000000000000000000000000000000000000015000000000000000700000000000000e5a3a7b5d830c2953b98534c6c59a3a34fdc34e933f7f5898f0a85cf08846bca0000000000000000000000000000000000000000000000000000000000000000dc9e2a7c6f948f17474e34a7fc43ed030f7c1563f1babddf6340c82e0e54a8c5000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000020006000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005d2eb8ae211693884eadaea0be0392c5532c7ff55429e4696c84954444d62ed600000000000000000000000000000000000000000000000000000000000000004f1cd2dde7dd5d4a9a495815f3ac76c56a77a9e06a5279a8c8550b54cf2d7287a630c3b9aefb94b1b6e8491eba4b43baa811c8f44167eb7d9ca933678ea64f5b2000000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f05005e0e00002d2d2d2d2d424547494e2043455254494649434154452d2d2d2d2d0a4d49494538544343424a656741774942416749554439426b736e734170713045567861464a59785a56794f6774664d77436759494b6f5a497a6a3045417749770a634445694d434147413155454177775a535735305a577767553064594946424453794251624746305a6d397962534244515445614d42674741315545436777520a535735305a577767513239796347397959585270623234784644415342674e564241634d43314e68626e526849454e7359584a684d51737743515944565151490a44414a445154454c4d416b474131554542684d4356564d774868634e4d6a55774d6a41334d5463774f4441325768634e4d7a49774d6a41334d5463774f4441320a576a42774d534977494159445651514444426c4a626e526c624342545231676755454e4c49454e6c636e52705a6d6c6a5958526c4d526f77474159445651514b0a4442464a626e526c6243424462334a7762334a6864476c76626a45554d424947413155454277774c553246756447456751327868636d4578437a414a42674e560a4241674d416b4e424d517377435159445651514745774a56557a425a4d424d4742797147534d34394167454743437147534d34394177454841304941424853770a3977506a72554532734f4a644c5653415434686565414a572b31796c6473615556696b5a4c485832506235777374326a79697539414f5865576a7a6a6d585a4c0a4343742b457858716f53394e45476c6b52724b6a67674d4e4d4949444354416642674e5648534d4547444157674253566231334e765276683655424a796454300a4d383442567776655644427242674e56485238455a4442694d47436758714263686c706f64485277637a6f764c32467761533530636e567a6447566b633256790a646d6c6a5a584d75615735305a577775593239744c334e6e6543396a5a584a3061575a7059324630615739754c3359304c33426a61324e796244396a595431770a624746305a6d397962535a6c626d4e765a476c755a7a316b5a584977485159445652304f42425945464d6a464e59626f7464634b636859487258467966774b460a774e534d4d41344741315564447745422f775145417749477744414d42674e5648524d4241663845416a41414d4949434f67594a4b6f5a496876684e415130420a424949434b7a4343416963774867594b4b6f5a496876684e41513042415151514134346b35686a336951797044574873756f5a474144434341575147436971470a534962345451454e41514977676746554d42414743797147534962345451454e41514942416745434d42414743797147534962345451454e41514943416745430a4d42414743797147534962345451454e41514944416745434d42414743797147534962345451454e41514945416745434d42414743797147534962345451454e0a41514946416745434d42454743797147534962345451454e41514947416749412f7a415142677371686b69472b453042445145434277494241444151426773710a686b69472b4530424451454343414942416a415142677371686b69472b45304244514543435149424144415142677371686b69472b45304244514543436749420a4144415142677371686b69472b45304244514543437749424144415142677371686b69472b45304244514543444149424144415142677371686b69472b4530420a44514543445149424144415142677371686b69472b45304244514543446749424144415142677371686b69472b453042445145434477494241444151426773710a686b69472b45304244514543454149424144415142677371686b69472b45304244514543455149424454416642677371686b69472b45304244514543456751510a4167494341674c2f4141494141414141414141414144415142676f71686b69472b45304244514544424149414144415542676f71686b69472b453042445145450a424159676f473841414141774477594b4b6f5a496876684e4151304242516f424154416542676f71686b69472b453042445145474242414b496f456755387a650a486d2b49596f7a686c337a314d45514743697147534962345451454e415163774e6a415142677371686b69472b45304244514548415145422f7a4151426773710a686b69472b45304244514548416745422f7a415142677371686b69472b45304244514548417745422f7a414b42676771686b6a4f5051514441674e49414442460a4169417362735a44796d2f72455a30476c454c62442f6e64755061536a485341746e5871567453313047486255774968414d585666784b334b666f4b675131660a4578397478765331314362363662323467424344523963477942562b0a2d2d2d2d2d454e442043455254494649434154452d2d2d2d2d0a2d2d2d2d2d424547494e2043455254494649434154452d2d2d2d2d0a4d4949436c6a4343416a32674177494241674956414a567658633239472b487051456e4a3150517a7a674658433935554d416f4743437147534d343942414d430a4d476778476a415942674e5642414d4d45556c756447567349464e48574342536232393049454e424d526f77474159445651514b4442464a626e526c624342440a62334a7762334a6864476c76626a45554d424947413155454277774c553246756447456751327868636d4578437a414a42674e564241674d416b4e424d5173770a435159445651514745774a56557a4165467730784f4441314d6a45784d4455774d5442614677307a4d7a41314d6a45784d4455774d5442614d484178496a41670a42674e5642414d4d47556c756447567349464e4857434251513073675547786864475a76636d306751304578476a415942674e5642416f4d45556c75644756730a49454e76636e4276636d4630615739754d5251774567594456515148444174545957353059534244624746795954454c4d416b474131554543417743513045780a437a414a42674e5642415954416c56544d466b77457759484b6f5a497a6a3043415159494b6f5a497a6a304441516344516741454e53422f377432316c58534f0a3243757a7078773734654a423732457944476757357258437478327456544c7136684b6b367a2b5569525a436e71523770734f766771466553786c6d546c4a6c0a65546d693257597a33714f42757a43427544416642674e5648534d4547444157674251695a517a575770303069664f44744a5653763141624f536347724442530a42674e5648523845537a424a4d45656752614244686b466f64485277637a6f764c324e6c636e52705a6d6c6a5958526c63793530636e567a6447566b633256790a646d6c6a5a584d75615735305a577775593239744c306c756447567355306459556d397664454e424c6d526c636a416442674e5648513445466751556c5739640a7a62306234656c4153636e553944504f4156634c336c517744675944565230504151482f42415144416745474d42494741315564457745422f7751494d4159420a4166384341514177436759494b6f5a497a6a30454177494452774177524149675873566b6930772b6936565947573355462f32327561586530594a446a3155650a6e412b546a44316169356343494359623153416d4435786b66545670766f34556f79695359787244574c6d5552344349394e4b7966504e2b0a2d2d2d2d2d454e442043455254494649434154452d2d2d2d2d0a2d2d2d2d2d424547494e2043455254494649434154452d2d2d2d2d0a4d4949436a7a4343416a53674177494241674955496d554d316c71644e496e7a6737535655723951477a6b6e42717777436759494b6f5a497a6a3045417749770a614445614d4267474131554541777752535735305a5777675530645949464a766233516751304578476a415942674e5642416f4d45556c756447567349454e760a636e4276636d4630615739754d5251774567594456515148444174545957353059534244624746795954454c4d416b47413155454341774351304578437a414a0a42674e5642415954416c56544d423458445445344d4455794d5445774e4455784d466f58445451354d54497a4d54497a4e546b314f566f77614445614d4267470a4131554541777752535735305a5777675530645949464a766233516751304578476a415942674e5642416f4d45556c756447567349454e76636e4276636d46300a615739754d5251774567594456515148444174545957353059534244624746795954454c4d416b47413155454341774351304578437a414a42674e56424159540a416c56544d466b77457759484b6f5a497a6a3043415159494b6f5a497a6a3044415163445167414543366e45774d4449595a4f6a2f69505773437a61454b69370a314f694f534c52466857476a626e42564a66566e6b59347533496a6b4459594c304d784f346d717379596a6c42616c54565978465032734a424b357a6c4b4f420a757a43427544416642674e5648534d4547444157674251695a517a575770303069664f44744a5653763141624f5363477244425342674e5648523845537a424a0a4d45656752614244686b466f64485277637a6f764c324e6c636e52705a6d6c6a5958526c63793530636e567a6447566b63325679646d6c6a5a584d75615735300a5a577775593239744c306c756447567355306459556d397664454e424c6d526c636a416442674e564851344546675155496d554d316c71644e496e7a673753560a55723951477a6b6e4271777744675944565230504151482f42415144416745474d42494741315564457745422f7751494d4159424166384341514577436759490a4b6f5a497a6a3045417749445351417752674968414f572f35516b522b533943695344634e6f6f774c7550524c735747662f59693747535839344267775477670a41694541344a306c72486f4d732b586f356f2f7358364f39515778485241765a55474f6452513763767152586171493d0a2d2d2d2d2d454e442043455254494649434154452d2d2d2d2d0a0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
        let tee_quote = hex::decode(tee_quote).unwrap();

        ThresholdParameters {
            participants,
            threshold,
            tee_participant_info: TeeParticipantInfo {
                tee_quote,
                quote_collateral,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::primitives::{
        participants::{ParticipantId, Participants},
        test_utils::{
            gen_participant, gen_participants, gen_threshold_params, mock_tee_participant_info,
            set_test_env_for_tee_quote_verification,
        },
        thresholds::{Threshold, ThresholdParameters},
    };
    use crate::state::running::running_tests::gen_valid_params_proposal;
    use rand::Rng;

    #[test]
    fn test_threshold() {
        for _ in 0..20 {
            let v = rand::thread_rng().gen::<u64>();
            let x = Threshold::new(v);
            assert_eq!(v, x.value());
        }
    }

    #[test]
    fn test_validate_threshold() {
        let n = rand::thread_rng().gen_range(2..600) as u64;
        let min_threshold = ((n as f64) * 0.6).ceil() as u64;
        for k in 0..min_threshold {
            assert!(ThresholdParameters::validate_threshold(n, Threshold::new(k)).is_err());
        }
        for k in min_threshold..(n + 1) {
            assert!(ThresholdParameters::validate_threshold(n, Threshold::new(k)).is_ok());
        }
        assert!(ThresholdParameters::validate_threshold(n, Threshold::new(n + 1)).is_err());
    }

    #[test]
    fn test_threshold_parameters_constructor() {
        set_test_env_for_tee_quote_verification();

        let n: usize = rand::thread_rng().gen_range(2..600);
        let min_threshold = ((n as f64) * 0.6).ceil() as usize;

        let participants = gen_participants(n);
        for k in 1..min_threshold {
            let invalid_threshold = Threshold::new(k as u64);
            assert!(ThresholdParameters::new(
                participants.clone(),
                invalid_threshold,
                mock_tee_participant_info()
            )
            .is_err());
        }
        assert!(ThresholdParameters::new(
            participants.clone(),
            Threshold::new((n + 1) as u64),
            mock_tee_participant_info()
        )
        .is_err());
        for k in min_threshold..(n + 1) {
            let threshold = Threshold::new(k as u64);
            let tp = ThresholdParameters::new(
                participants.clone(),
                threshold.clone(),
                mock_tee_participant_info(),
            );
            assert!(tp.is_ok(), "{:?}", tp);
            let tp = tp.unwrap();
            assert!(tp.validate().is_ok());
            assert_eq!(tp.threshold(), threshold);
            assert_eq!(tp.participants.len(), participants.len());
            assert_eq!(participants, *tp.participants());
            // probably overkill to test below
            for (account_id, _, _) in participants.participants() {
                assert!(tp.participants.is_participant(account_id));
                let expected_id = participants.id(account_id).unwrap();
                assert_eq!(expected_id, tp.participants.id(account_id).unwrap());
                assert_eq!(
                    tp.participants.account_id(&expected_id).unwrap(),
                    *account_id
                );
            }
        }
    }

    #[test]
    fn test_validate_incoming_proposal() {
        set_test_env_for_tee_quote_verification();

        // Valid proposals should validate.
        let params = gen_threshold_params(10);
        let proposal = gen_valid_params_proposal(&params);
        assert!(params.validate_incoming_proposal(&proposal).is_ok());

        // Random proposals should not validate.
        let proposal = gen_threshold_params(10);
        assert!(params.validate_incoming_proposal(&proposal).is_err());

        // Proposal with threshold number of shared participants should be allowed.
        let mut new_participants = params
            .participants
            .subset(0..params.threshold.value() as usize);
        new_participants.add_random_participants_till_n(params.participants.len());
        let proposal =
            ThresholdParameters::new_unvalidated(new_participants, params.threshold.clone());
        assert!(
            params.validate_incoming_proposal(&proposal).is_ok(),
            "{:?} -> {:?}",
            params,
            proposal
        );

        // Proposal with less than threshold number of shared participants should not be allowed,
        // even if the new threshold is lower.
        let mut new_participants = params
            .participants
            .subset(0..params.threshold.value() as usize - 1);
        new_participants.add_random_participants_till_n(params.participants.len());
        let proposal = ThresholdParameters::new_unvalidated(
            new_participants,
            Threshold(params.threshold.value() - 1),
        );
        assert!(params.validate_incoming_proposal(&proposal).is_err());

        // Proposal with the new threshold being invalid should not be allowed.
        let mut new_participants = params
            .participants
            .subset(0..params.threshold.value() as usize);
        new_participants.add_random_participants_till_n(50);
        let proposal =
            ThresholdParameters::new_unvalidated(new_participants, params.threshold.clone());
        assert!(params.validate_incoming_proposal(&proposal).is_err());
    }

    #[test]
    fn test_proposal_non_contiguous_new_ids_fail() {
        set_test_env_for_tee_quote_verification();

        // Test that the lowest new id equals to the `next_id` of the previous set.

        let params = gen_threshold_params(10);

        let wrong_id = params.participants.next_id().0 + 1;

        let (account_id, participant_info) = gen_participant(wrong_id as usize);

        let mut tampered_participants = params.participants.clone();
        tampered_participants
            .insert_with_id(account_id, participant_info, ParticipantId(wrong_id))
            .unwrap();

        let tampered_params = ThresholdParameters {
            participants: tampered_participants,
            threshold: params.threshold.clone(),
            tee_participant_info: mock_tee_participant_info(),
        };

        let result = params.validate_incoming_proposal(&tampered_params);
        assert!(result.is_err());
    }

    #[test]
    fn test_proposal_non_unique_ids() {
        set_test_env_for_tee_quote_verification();

        let params = gen_threshold_params(10);

        // Add duplicate participants
        let tampered_participants = Participants::init(
            params.participants.next_id(),
            params
                .participants
                .participants()
                .iter()
                .chain(params.participants.participants().iter())
                .cloned()
                .collect(),
        );
        assert!(tampered_participants.validate().is_err());

        let tampered_params = ThresholdParameters {
            participants: tampered_participants,
            threshold: params.threshold.clone(),
            tee_participant_info: mock_tee_participant_info(),
        };
        assert!(params.validate_incoming_proposal(&tampered_params).is_err());
    }

    #[test]
    fn test_remove_only() {
        set_test_env_for_tee_quote_verification();

        let params = ThresholdParameters::new(
            gen_participants(5),
            Threshold::new(3),
            mock_tee_participant_info(),
        )
        .unwrap();

        let new_participants = params
            .participants
            .subset(0..params.threshold.value() as usize);

        let new_params = ThresholdParameters::new(
            new_participants,
            params.threshold.clone(),
            mock_tee_participant_info(),
        )
        .unwrap();

        let result = params.validate_incoming_proposal(&new_params);
        assert!(result.is_ok());
    }

    #[test]
    fn test_simultaneous_remove_and_insert() {
        set_test_env_for_tee_quote_verification();

        let n = 5;
        let params = ThresholdParameters::new(
            gen_participants(n),
            Threshold::new(3),
            mock_tee_participant_info(),
        )
        .unwrap();

        let mut new_participants = params.participants.clone();
        new_participants.add_random_participants_till_n(n + 2);
        let new_participants = new_participants.subset(2..n + 2);

        let new_params = ThresholdParameters::new(
            new_participants,
            params.threshold.clone(),
            mock_tee_participant_info(),
        )
        .unwrap();

        let result = params.validate_incoming_proposal(&new_params);
        assert!(result.is_ok());
    }

    #[test]
    fn test_new_participant_id_too_high() {
        set_test_env_for_tee_quote_verification();

        // Test the logic that `next_id` should only be equal to `max_id + 1`

        let n = 5;
        let params = ThresholdParameters::new(
            gen_participants(n),
            Threshold::new(3),
            mock_tee_participant_info(),
        )
        .unwrap();

        for i in 0..=params.participants.next_id().0 + 2 {
            let new_participants =
                Participants::init(ParticipantId(i), params.participants.participants().clone());
            let new_params = ThresholdParameters::new(
                new_participants,
                params.threshold.clone(),
                mock_tee_participant_info(),
            )
            .unwrap();
            let result = params.validate_incoming_proposal(&new_params);
            if i >= params.participants.next_id().0 {
                assert!(result.is_ok());
            } else {
                assert!(
                    result.is_err(),
                    "i: {}, max_id: {}",
                    i,
                    new_params.participants.next_id().0
                );
            }
        }
    }
}
