Example usage:

```
TEST_SEED="71,08,70,63,09,6d,77,b5,36,ac,4a,36,6c,31,fe,de,81,5e,a9,02,fa,a6,61,ef,9a,32,b4,b4,9a,5d,6c,7c" \
cargo test -- --nocapture
```

```
TEST_SEED="71,08,70,63,09,6d,77,b5,36,ac,4a,36,6c,31,fe,de,81,5e,a9,02,fa,a6,61,ef,9a,32,b4,b4,9a,5d,6c,7c" cargo nextest run --release -- test_fails_sometimes
```
