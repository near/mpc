pub const BEARER_TOKEN: &str = "secret_bearer_token_123";
pub static SERVER_KEYPAIR: LazyLock<Keypair> =
    LazyLock::new(|| Keypair::new_global(&mut secp256k1::rand::rngs::StdRng::seed_from_u64(42)));
pub static CLIENT_KEYPAIR: LazyLock<Keypair> =
    LazyLock::new(|| Keypair::new_global(&mut secp256k1::rand::rngs::StdRng::seed_from_u64(1337)));

use std::sync::LazyLock;

use secp256k1::{Keypair, rand::SeedableRng as _};
