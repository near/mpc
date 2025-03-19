use rand::Rng;

fn main() {
    let sign_sk = near_crypto::SecretKey::from_random(near_crypto::KeyType::ED25519);
    let sign_pk = sign_sk.public_key();
    println!("p2p public key sign_pk: {}", sign_pk);
    println!("p2p secret key sign_sk: {}", sign_sk);
    let near_account_sk = near_crypto::SecretKey::from_random(near_crypto::KeyType::ED25519);
    let near_account_pk = near_account_sk.public_key();
    println!("near account public key: {}", near_account_pk);
    println!("near account secret key: {}", near_account_sk);
    let mut rng = rand::thread_rng();
    let random_bytes: [u8; 16] = rng.gen();
    let hex_string: String = random_bytes.iter().map(|byte| format!("{:02x}", byte)).collect();
    println!("near local encryption key: {}", hex_string.to_uppercase());
}