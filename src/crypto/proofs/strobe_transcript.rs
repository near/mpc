use zeroize::Zeroize;

use crate::crypto::constants::MERLIN_PROTOCOL_LABEL;

use super::strobe::Strobe128;

fn encode_array_len_as_u32(array: &[u8]) -> [u8; 4] {
    use byteorder::{ByteOrder, LittleEndian};

    // This should never panic
    let x = u32::try_from(array.len()).unwrap();

    let mut buf = [0; 4];
    LittleEndian::write_u32(&mut buf, x);
    buf
}

#[derive(Clone, Zeroize)]
pub struct Transcript {
    strobe: Strobe128,
}

impl Transcript {
    /// Initialize a new transcript with the supplied `label`, which
    /// is used as a domain separator.
    ///
    /// # Note
    ///
    /// This function should be called by a proof library's API
    /// consumer (i.e., the application using the proof library), and
    /// **not by the proof implementation**.  See the [Passing
    /// Transcripts](https://merlin.cool/use/passing.html) section of
    /// the Merlin website for more details on why.
    pub fn new(label: &'static [u8]) -> Self {
        let mut transcript = Self {
            strobe: Strobe128::new(MERLIN_PROTOCOL_LABEL),
        };
        transcript.message(b"dom-sep", label);

        transcript
    }

    /// Append a prover's `message` to the transcript.
    ///
    /// The `label` parameter is metadata about the message, and is
    /// also appended to the transcript.  See the [Transcript
    /// Protocols](https://merlin.cool/use/protocol.html) section of
    /// the Merlin website for details on labels.
    pub fn message(&mut self, label: &'static [u8], message: &[u8]) {
        let data_len = encode_array_len_as_u32(message);
        self.strobe.meta_ad(label, false);
        self.strobe.meta_ad(&data_len, true);
        self.strobe.ad(message, false);
    }

    /// Fill the supplied buffer with the verifier's challenge bytes.
    ///
    /// The `label` parameter is metadata about the challenge, and is
    /// also appended to the transcript.  See the [Transcript
    /// Protocols](https://merlin.cool/use/protocol.html) section of
    /// the Merlin website for details on labels.
    pub fn challenge(&mut self, label: &'static [u8], dest: &mut [u8]) {
        let data_len = encode_array_len_as_u32(dest);
        self.strobe.meta_ad(label, false);
        self.strobe.meta_ad(&data_len, true);
        self.strobe.prf(dest, false);
    }

    /// Create a forked version of this transcript.
    ///
    /// This is often useful in the context of cryptographic protocols. You
    /// might want to verify multiple proofs generated at the some point
    /// in the transcript, but by different people. You can use this primitive
    /// to fork the transcript to check those proofs, with some domain separation
    /// identifying each person.
    ///
    /// Forking without domain separation is intentionally not possible, to prevent
    /// potential misuse where the same randomness is generated in different contexts.
    pub fn fork(&self, label: &'static [u8], data: &[u8]) -> Self {
        let mut out = self.clone();
        out.message(label, data);
        out
    }

    /// Consumes the Transcript to build an RNG
    pub fn build_rng(&mut self, seed: &[u8; 32]) -> TranscriptRng {
        self.strobe.meta_ad(b"rng from seed", false);
        self.strobe.key(seed, false);

        TranscriptRng {
            strobe: self.strobe.clone(),
        }
    }

    /// Runs a challenge and then builds an rng from it
    pub fn challenge_then_build_rng(&mut self, challenge_label: &'static [u8]) -> TranscriptRng {
        let mut seed = [0u8; 32];
        self.challenge(challenge_label, &mut seed);
        self.build_rng(&seed)
    }
}

pub struct TranscriptRng {
    strobe: Strobe128,
}

impl TranscriptRng {
    pub fn new(seed: &[u8; 32]) -> Self {
        let mut t = Transcript::new(b"direct RNG from seed");
        t.build_rng(seed)
    }
}

impl rand_core::RngCore for TranscriptRng {
    fn next_u32(&mut self) -> u32 {
        rand_core::impls::next_u32_via_fill(self)
    }

    fn next_u64(&mut self) -> u64 {
        rand_core::impls::next_u64_via_fill(self)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let dest_len = encode_array_len_as_u32(dest);
        self.strobe.meta_ad(&dest_len, false);
        self.strobe.prf(dest, false);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl rand_core::CryptoRng for TranscriptRng {}
