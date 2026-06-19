use super::*;
use crate::crypto::cheetah_tip5::belt::{montify, Belt};

// assert that input is made of base field elements
pub fn assert_all_based(vecbelt: &Vec<Belt>) {
    vecbelt.iter().for_each(|b| based!(b.0));
}

// calc q and r for vecbelt, based on RATE
pub fn tip5_calc_q_r(input_vec: &[Belt]) -> (usize, usize) {
    let lent_input = input_vec.len();
    let (q, r) = (lent_input / RATE, lent_input % RATE);
    (q, r)
}

// pad vecbelt with ~[1 0 ... 0] to be a multiple of rate
pub fn tip5_pad_vecbelt(input_vec: &mut Vec<Belt>, r: usize) {
    input_vec.push(Belt(1));
    for _i in 0..(RATE - r) - 1 {
        input_vec.push(Belt(0));
    }
}

// monitify vecbelt (bring into montgomery space)
pub fn tip5_montify_vecbelt(input_vec: &mut [Belt]) {
    for belt in input_vec.iter_mut() {
        *belt = Belt(montify(belt.0));
    }
}

// calc digest
pub fn tip5_calc_digest(sponge: &[u64; 16]) -> [u64; 5] {
    let mut digest = [0u64; DIGEST_LENGTH];
    for i in 0..DIGEST_LENGTH {
        digest[i] = mont_reduction(sponge[i] as u128);
    }
    digest
}

// absorb complete input
pub fn tip5_absorb_input(input_vec: &mut Vec<Belt>, sponge: &mut [u64; 16], q: usize) {
    let mut cnt_q = q;
    let mut input_to_absorb = input_vec.as_slice();
    loop {
        let (scag_input, slag_input) = input_to_absorb.split_at(RATE);
        tip5_absorb_rate(sponge, scag_input);

        if cnt_q == 0 {
            break;
        }
        cnt_q -= 1;
        input_to_absorb = slag_input;
    }
}

// absorb one part of input (size RATE)
pub fn tip5_absorb_rate(sponge: &mut [u64; 16], input: &[Belt]) {
    assert_eq!(input.len(), RATE);

    for copy_pos in 0..RATE {
        sponge[copy_pos] = input[copy_pos].0;
    }

    permute(sponge);
}

#[inline(always)]
fn absorb_preprocess(input: &[u64]) -> Vec<u64> {
    let r = input.len() % RATE;
    let mut padded = vec![0; input.len() + RATE - r];
    padded[..input.len()].copy_from_slice(input);
    padded[input.len()] = MONT_ONE;
    padded
}

#[inline(always)]
fn hash_ten_cell_mont(input: [u64; RATE]) -> [u64; DIGEST_LENGTH] {
    let mut sponge: [u64; STATE_SIZE] = [0; STATE_SIZE];
    sponge[..RATE].copy_from_slice(&input);
    for item in sponge.iter_mut().skip(RATE) {
        *item = MONT_ONE;
    }

    permute(&mut sponge);

    sponge[..DIGEST_LENGTH]
        .try_into()
        .expect("digest length should match")
}

#[inline(always)]
pub fn hash_ten_cell(input: [u64; RATE]) -> [u64; DIGEST_LENGTH] {
    let mut monted = [0; RATE];
    for i in 0..RATE {
        based!(input[i]);
        monted[i] = montify(input[i]);
    }

    let mut res = hash_ten_cell_mont(monted);
    for item in &mut res {
        *item = mont_reduction(*item as u128);
    }
    res
}

#[inline(always)]
pub fn hash_belts_slice(input: &[u64]) -> [u64; DIGEST_LENGTH] {
    let q = input.len() / RATE;
    let mut padded = absorb_preprocess(input);

    for i in 0..input.len() {
        based!(input[i]);
        padded[i] = montify(input[i]);
    }

    let mut sponge: [u64; STATE_SIZE] = [0; STATE_SIZE];
    let mut padded_ref = &padded[..];
    for _ in 0..=q {
        sponge[..RATE].copy_from_slice(&padded_ref[..RATE]);
        permute(&mut sponge);
        padded_ref = &padded_ref[RATE..];
    }

    tip5_calc_digest(&sponge)
}

#[inline(always)]
pub fn absorb(sponge: &mut [u64; STATE_SIZE], input: &[u64]) {
    let q = input.len() / RATE;
    let mut padded = absorb_preprocess(input);

    for i in 0..input.len() {
        based!(input[i]);
        padded[i] = montify(input[i]);
    }

    let mut padded_ref = &padded[..];
    for _ in 0..=q {
        sponge[..RATE].copy_from_slice(&padded_ref[..RATE]);
        permute(sponge);
        padded_ref = &padded_ref[RATE..];
    }
}

#[inline(always)]
pub fn squeeze(sponge: &mut [u64; STATE_SIZE]) -> [u64; RATE] {
    let mut res = [0; RATE];
    for i in 0..RATE {
        res[i] = mont_reduction(sponge[i] as u128);
    }
    permute(sponge);
    res
}

pub fn hash_varlen(input_vec: &mut Vec<Belt>) -> [u64; 5] {
    assert_all_based(input_vec);
    let input = input_vec.iter().map(|belt| belt.0).collect::<Vec<_>>();
    hash_belts_slice(&input)
}

pub fn create_init_sponge_variable() -> [u64; STATE_SIZE] {
    [0u64; STATE_SIZE]
}
pub fn create_init_sponge_fixed() -> [u64; STATE_SIZE] {
    [
        0u64, 0u64, 0u64, 0u64, 0u64, 0u64, 0u64, 0u64, 0u64, 0u64, 4294967295u64, 4294967295u64,
        4294967295u64, 4294967295u64, 4294967295u64, 4294967295u64,
    ]
}

pub fn hash_10(input_vec: &mut Vec<Belt>) -> [u64; 5] {
    // check input
    let (q, r) = tip5_calc_q_r(input_vec);
    assert_eq!(q, 1);
    assert_eq!(r, 0);
    assert_all_based(input_vec);

    let input: [u64; RATE] = input_vec
        .iter()
        .map(|belt| belt.0)
        .collect::<Vec<_>>()
        .try_into()
        .expect("hash_10 input should have RATE elements");
    hash_ten_cell(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tip5_hash_varlen_public_vectors() {
        let mut empty = vec![];
        assert_eq!(
            hash_varlen(&mut empty),
            [
                11048995573592393898, 6655187932135147625, 8573492257662932655,
                4379820112787053727, 3881663824627898703,
            ]
        );

        let mut one = vec![Belt(2)];
        assert_eq!(
            hash_varlen(&mut one),
            [
                8342164316692288712, 12061287490523852513, 4038969618836824144,
                5830796451787599265, 468390350313364562,
            ]
        );

        let mut two = vec![Belt(5), Belt(26)];
        assert_eq!(
            hash_varlen(&mut two),
            [
                4045697570544439560, 13674194094340317530, 13743008867885290460,
                6020910684025273897, 3362765570390427021,
            ]
        );

        let mut ten = vec![
            Belt(1),
            Belt(2448),
            Belt(1),
            Belt(0),
            Belt(0),
            Belt(0),
            Belt(0),
            Belt(0),
            Belt(0),
            Belt(0),
        ];
        assert_eq!(
            hash_varlen(&mut ten),
            [
                12811986333282368874, 13601598673786067780, 3807788325936413287,
                5511165615113400862, 11490077061305916457,
            ]
        );
    }
}
