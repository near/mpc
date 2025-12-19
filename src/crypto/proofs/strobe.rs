//! Fully imported from zkcrypto/merlin project specifically from
//! <https://github.com/zkcrypto/merlin/blob/main/src/strobe.rs>
//! except for the test cases to prevent importing `strobe_rs` crate into the project
//! Modified to avoid using unsafe code

//! Minimal implementation of (parts of) Strobe.

// # TODO(#122): remove this exception
#![allow(clippy::indexing_slicing)]

use derive_more::{Deref, DerefMut};
use zeroize::Zeroize;

use crate::crypto::constants::{FLAG_A, FLAG_C, FLAG_I, FLAG_K, FLAG_M, FLAG_T, STROBE_R};

fn transmute_state(st: &KeccakState) -> [u64; 25] {
    let mut result = [0u64; 25];
    for (i, resulti) in result.iter_mut().enumerate() {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&st[8 * i..8 * i + 8]);
        *resulti = u64::from_le_bytes(bytes);
    }
    result
}

fn untransmute_state(transmuted_state: [u64; 25], state: &mut KeccakState) {
    for (i, ti) in transmuted_state.iter().enumerate() {
        state[8 * i..8 * i + 8].copy_from_slice(&ti.to_le_bytes());
    }
}

fn keccak_f1600_wrapper(state: &mut KeccakState) {
    let mut transmuted_state = transmute_state(state);
    keccak::f1600(&mut transmuted_state);
    untransmute_state(transmuted_state, state);
}

#[derive(Clone, Zeroize, Deref, DerefMut)]
#[zeroize(drop)]
struct KeccakState([u8; 200]);

/// A Strobe context for the 128-bit security level.
///
/// Only `meta-AD`, `AD`, `KEY`, and `PRF` operations are supported.
#[derive(Clone, Zeroize)]
pub struct Strobe128 {
    state: KeccakState,
    pos: u8,
    pos_begin: u8,
    cur_flags: u8,
}

impl ::core::fmt::Debug for Strobe128 {
    fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        // Ensure that the Strobe state isn't accidentally logged
        write!(f, "Strobe128: STATE OMITTED")
    }
}

impl Strobe128 {
    pub fn new(protocol_label: &[u8]) -> Self {
        let initial_state = {
            let mut st = KeccakState([0u8; 200]);
            st[0..6].copy_from_slice(&[1, STROBE_R + 2, 1, 0, 1, 96]);
            st[6..18].copy_from_slice(b"STROBEv1.0.2");
            keccak_f1600_wrapper(&mut st);
            st
        };

        let mut strobe = Self {
            state: initial_state,
            pos: 0,
            pos_begin: 0,
            cur_flags: 0,
        };

        strobe.meta_ad(protocol_label, false);

        strobe
    }

    pub fn meta_ad(&mut self, data: &[u8], more: bool) {
        self.begin_op(FLAG_M | FLAG_A, more);
        self.absorb(data);
    }

    pub fn ad(&mut self, data: &[u8], more: bool) {
        self.begin_op(FLAG_A, more);
        self.absorb(data);
    }

    pub fn prf(&mut self, data: &mut [u8], more: bool) {
        self.begin_op(FLAG_I | FLAG_A | FLAG_C, more);
        self.squeeze(data);
    }

    pub fn key(&mut self, data: &[u8], more: bool) {
        self.begin_op(FLAG_A | FLAG_C, more);
        self.overwrite(data);
    }
}

impl Strobe128 {
    fn run_f(&mut self) {
        self.state[self.pos as usize] ^= self.pos_begin;
        self.state[(self.pos + 1) as usize] ^= 0x04;
        self.state[(STROBE_R + 1) as usize] ^= 0x80;
        keccak_f1600_wrapper(&mut self.state);
        self.pos = 0;
        self.pos_begin = 0;
    }

    fn absorb(&mut self, data: &[u8]) {
        for byte in data {
            self.state[self.pos as usize] ^= byte;
            self.pos += 1;
            if self.pos == STROBE_R {
                self.run_f();
            }
        }
    }

    fn overwrite(&mut self, data: &[u8]) {
        for byte in data {
            self.state[self.pos as usize] = *byte;
            self.pos += 1;
            if self.pos == STROBE_R {
                self.run_f();
            }
        }
    }

    fn squeeze(&mut self, data: &mut [u8]) {
        for byte in data {
            *byte = self.state[self.pos as usize];
            self.state[self.pos as usize] = 0;
            self.pos += 1;
            if self.pos == STROBE_R {
                self.run_f();
            }
        }
    }

    fn begin_op(&mut self, flags: u8, more: bool) {
        // Check if we're continuing an operation
        if more {
            assert_eq!(
                self.cur_flags, flags,
                "You tried to continue op {:#b} but changed flags to {:#b}",
                self.cur_flags, flags,
            );
            return;
        }

        // Skip adjusting direction information (we just use AD, PRF)
        assert_eq!(
            flags & FLAG_T,
            0u8,
            "You used the T flag, which this implementation doesn't support"
        );

        let old_begin = self.pos_begin;
        self.pos_begin = self.pos + 1;
        self.cur_flags = flags;

        self.absorb(&[old_begin, flags]);

        // Force running F if C or K is set
        let force_f = 0 != (flags & (FLAG_C | FLAG_K));

        if force_f && self.pos != 0 {
            self.run_f();
        }
    }
}
