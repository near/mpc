use test_macros::with_rng;

#[with_rng]
fn test_basic() {
    let x = rng.gen_range(0..10);
    assert!(x < 10);
}

#[with_rng]
fn test_fails_sometimes() {
    let x = rng.gen_range(0..2);
    assert_eq!(x, 1);
}
