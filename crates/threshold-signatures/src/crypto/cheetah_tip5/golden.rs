//! Byte-exact parity regression against `@nockchain/rose-ts`, ported from the
//! retired `cheetah-frost` crate.
//!
//! Reproduces the deterministic single-signer and the 2-party additive (FROST
//! core) Cheetah Schnorr signatures from the TS spike's golden vectors
//! (`atomic-nock-solver/scripts/cheetah-threshold-spike.ts`), using only the
//! vendored primitives. Matching the exact `(c, s)` rose-ts produced confirms the
//! whole signature scheme — not just the primitives — is byte-identical to
//! rose-ts / the on-chain Nockchain verifier.

use ibig::UBig;
use serde_json::Value;

use super::belt::Belt;
use super::cheetah::{ch_add, ch_neg, ch_scal_big, trunc_g_order, CheetahPoint, A_GEN, G_ORDER};
use super::tip5::hash::hash_varlen;

const GOLDEN: &str = include_str!("golden-vectors.json");

fn pubkey(secret: &UBig) -> CheetahPoint {
    ch_scal_big(secret, &A_GEN).expect("scalar mul on generator")
}

/// `c = trunc_g_order(Tip5(R.x‖R.y‖P.x‖P.y‖m))`.
fn challenge(r: &CheetahPoint, p: &CheetahPoint, m: &[u64; 5]) -> UBig {
    let mut t: Vec<Belt> = Vec::with_capacity(29);
    t.extend_from_slice(&r.x.0);
    t.extend_from_slice(&r.y.0);
    t.extend_from_slice(&p.x.0);
    t.extend_from_slice(&p.y.0);
    t.extend(m.iter().map(|&u| Belt(u)));
    trunc_g_order(&hash_varlen(&mut t))
}

fn sign_with_nonce(secret: &UBig, nonce: &UBig, m: &[u64; 5]) -> (UBig, UBig) {
    let p = pubkey(secret);
    let r = pubkey(nonce);
    let chal = challenge(&r, &p, m);
    let cs = (&chal * secret) % &*G_ORDER;
    let sig = (nonce.clone() + cs) % &*G_ORDER;
    (chal, sig)
}

/// rose-ts deterministic nonce: `trunc_g_order(Tip5(P.x‖P.y‖m‖limbs(secret_le32)))`,
/// where the secret's 32 little-endian bytes are split into eight LE 32-bit limbs.
fn deterministic_nonce(key_be: &[u8; 32], p: &CheetahPoint, m: &[u64; 5]) -> UBig {
    let mut le = [0u8; 32];
    for i in 0..32 {
        le[i] = key_be[31 - i];
    }
    let mut limbs = [0u64; 8];
    for i in 0..8 {
        let mut v = 0u64;
        for j in 0..4 {
            v |= (le[i * 4 + j] as u64) << (j * 8);
        }
        limbs[i] = v;
    }
    let mut t: Vec<Belt> = Vec::with_capacity(25);
    t.extend_from_slice(&p.x.0);
    t.extend_from_slice(&p.y.0);
    t.extend(m.iter().map(|&u| Belt(u)));
    t.extend(limbs.iter().map(|&u| Belt(u)));
    trunc_g_order(&hash_varlen(&mut t))
}

/// Mirrors the on-chain verifier: accept iff `trunc_g_order(Tip5((s·G − c·P)‖P‖m)) == c`.
fn verify(p: &CheetahPoint, chal: &UBig, sig: &UBig, m: &[u64; 5]) -> bool {
    let left = ch_scal_big(sig, &A_GEN).expect("sG");
    let right = ch_neg(&ch_scal_big(chal, p).expect("cP"));
    let rprime = ch_add(&left, &right).expect("R'");
    &challenge(&rprime, p, m) == chal
}

/// 97-byte wire form: `0x01 ‖ y-limbs(reversed, BE) ‖ x-limbs(reversed, BE)`.
fn point_to_be_bytes(p: &CheetahPoint) -> [u8; 97] {
    let mut o = [0u8; 97];
    o[0] = 0x01;
    let mut i = 1;
    for b in p.y.0.iter().rev() {
        o[i..i + 8].copy_from_slice(&b.0.to_be_bytes());
        i += 8;
    }
    for b in p.x.0.iter().rev() {
        o[i..i + 8].copy_from_slice(&b.0.to_be_bytes());
        i += 8;
    }
    o
}

fn hex_to_bytes(h: &str) -> Vec<u8> {
    (0..h.len() / 2)
        .map(|i| u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).unwrap())
        .collect()
}
/// Golden `c`/`s`/`x_i`/`k_i` are little-endian hex of the scalar value.
fn ubig_le_hex(h: &str) -> UBig {
    UBig::from_le_bytes(&hex_to_bytes(h))
}
/// `keyHex` is big-endian; ibig 0.3 lacks `from_be_bytes`, so reverse then LE.
fn ubig_be_hex(h: &str) -> UBig {
    let mut b = hex_to_bytes(h);
    b.reverse();
    UBig::from_le_bytes(&b)
}
fn key32(h: &str) -> [u8; 32] {
    let mut o = [0u8; 32];
    o.copy_from_slice(&hex_to_bytes(h));
    o
}
fn belts5(v: &Value) -> [u64; 5] {
    let a = v.as_array().unwrap();
    let mut o = [0u64; 5];
    for i in 0..5 {
        o[i] = a[i].as_str().unwrap().parse().unwrap();
    }
    o
}
fn pk_hex(p: &CheetahPoint) -> String {
    point_to_be_bytes(p).iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn golden_deterministic_single_matches_rose_ts() {
    let g: Value = serde_json::from_str(GOLDEN).unwrap();
    let d = &g["deterministic_single"];
    let key_hex = d["keyHex"].as_str().unwrap();
    let key = key32(key_hex);
    let secret = ubig_be_hex(key_hex);
    let m = belts5(&d["digestBelts"]);

    let p = pubkey(&secret);
    let nonce = deterministic_nonce(&key, &p, &m);
    let (chal, sig) = sign_with_nonce(&secret, &nonce, &m);

    assert_eq!(pk_hex(&p), d["pubkeyHex"].as_str().unwrap(), "pubkey bytes");
    assert_eq!(chal, ubig_le_hex(d["c"].as_str().unwrap()), "challenge c");
    assert_eq!(sig, ubig_le_hex(d["s"].as_str().unwrap()), "response s");
    assert!(verify(&p, &chal, &sig, &m), "self-verify");
}

#[test]
fn golden_additive_2party_matches_rose_ts() {
    let g: Value = serde_json::from_str(GOLDEN).unwrap();
    let a = &g["additive_2party"];
    let x1 = ubig_le_hex(a["x1"].as_str().unwrap());
    let x2 = ubig_le_hex(a["x2"].as_str().unwrap());
    let k1 = ubig_le_hex(a["k1"].as_str().unwrap());
    let k2 = ubig_le_hex(a["k2"].as_str().unwrap());
    let m = belts5(&a["m"]);

    let p = ch_add(&pubkey(&x1), &pubkey(&x2)).expect("P = P1 + P2");
    let r = ch_add(&pubkey(&k1), &pubkey(&k2)).expect("R = R1 + R2");
    let chal = challenge(&r, &p, &m);
    let cs1 = (&chal * &x1) % &*G_ORDER;
    let cs2 = (&chal * &x2) % &*G_ORDER;
    let s1 = (k1 + cs1) % &*G_ORDER;
    let s2 = (k2 + cs2) % &*G_ORDER;
    let sig = (s1 + s2) % &*G_ORDER;

    assert_eq!(pk_hex(&p), a["pubkeyHex"].as_str().unwrap(), "aggregate pubkey bytes");
    assert_eq!(chal, ubig_le_hex(a["c"].as_str().unwrap()), "challenge c");
    assert_eq!(sig, ubig_le_hex(a["s"].as_str().unwrap()), "aggregate s");
    assert!(verify(&p, &chal, &sig, &m), "threshold signature verifies");
}
