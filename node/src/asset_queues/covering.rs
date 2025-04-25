use bit_set::BitSet;
use itertools::Itertools;
use rand::seq::IteratorRandom;
use rand::{RngCore, SeedableRng};

pub type CoveringSet = BitSet<u64>;

fn random_subset(rng: &mut impl RngCore, v: usize, k: usize) -> CoveringSet {
    assert!(k <= v);
    let mut subset = CoveringSet::default();
    for i in (0..v).choose_multiple(rng, k) {
        subset.insert(i);
    }
    subset
}

/// Copied from itertools.
fn checked_binomial(mut n: usize, mut k: usize) -> Option<usize> {
    if n < k {
        return Some(0);
    }
    // `factorial(n) / factorial(n - k) / factorial(k)` but trying to avoid it overflows:
    k = (n - k).min(k); // symmetry
    let mut c = 1;
    for i in 1..=k {
        c = (c / i)
            .checked_mul(n)?
            .checked_add((c % i).checked_mul(n)? / i)?;
        n -= 1;
    }
    Some(c)
}

pub fn make_covering_randomly(
    rng: &mut impl RngCore,
    v: usize,
    k: usize,
    n: usize,
) -> Vec<CoveringSet> {
    let mut coverings = Vec::new();
    if checked_binomial(v, k).is_some_and(|c| c <= 10 * n) {
        // If the number of combinations is small enough, we can just generate all of them
        // and sample from them; because otherwise the rejection sampling below (ensuring
        // coverings are distinct) will be too slow.
        for combination in (0..v).combinations(k).choose_multiple(rng, n) {
            let mut subset = CoveringSet::default();
            for i in combination {
                subset.insert(i);
            }
            coverings.push(subset);
        }
    } else {
        for _ in 0..n {
            let covering = random_subset(rng, v, k);
            coverings.push(covering);
        }
    }
    coverings
}

#[cfg(test)]
mod tests {
    use super::make_covering_randomly;
    use crate::asset_queues::covering::random_subset;
    use rand::{thread_rng, SeedableRng};

    #[test]
    fn test_covering_probability() {
        for v in [8, 10, 20, 30, 40, 50, 60, 70] {
            let k = v * 4 / 10;
            let n = 50;
            let mut rng = rand_pcg::Pcg64::seed_from_u64(0);
            let covering = make_covering_randomly(&mut rng, v, k, n);
            for r in [1, 2, 3, 4] {
                if r * 10 > v {
                    continue;
                }
                let mut at_least_one_survives = 0;
                let mut random_survival = 0;
                let mut covering_survival = 0;
                let iters = 10000;
                for i in 0..iters {
                    let subset = random_subset(&mut thread_rng(), v, r);
                    let survived = covering.iter().filter(|c| c.is_superset(&subset)).count();
                    if survived > 0 {
                        at_least_one_survives += 1;
                        covering_survival += survived;
                    }
                    for _ in 0..n {
                        let random_cover = random_subset(&mut thread_rng(), v, k);
                        if random_cover.is_superset(&subset) {
                            random_survival += 1;
                        }
                    }
                }
                let at_least_one_survives_prob = at_least_one_survives as f64 / iters as f64;
                let random_survival_rate = random_survival as f64 / iters as f64 / n as f64;
                let covering_survival_rate =
                    covering_survival as f64 / iters as f64 / covering.len() as f64;
                println!(
                    "v: {}, k: {}, n: {}, r: {}, covering rate: {}, random survival: {}, covering survival: {}",
                    v, k, n, r, at_least_one_survives_prob, random_survival_rate, covering_survival_rate
                );
            }
        }
    }
}
