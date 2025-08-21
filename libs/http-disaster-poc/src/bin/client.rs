#[tokio::main]
async fn main() {
    println!("Getting original secret");
    let secret = get_secret().await;
    println!("Secret: {secret}\n");

    let new_secret = "Build projects around motivated individuals.
Give them the environment and support they need,
and trust them to get the job done.";

    println!("Setting a new secret: {new_secret}\n");
    set_secret(new_secret).await;

    let latest_secret = get_secret().await;
    println!("Latest secret: {latest_secret}\n");
}

async fn get_secret() -> String {
    let client = reqwest::Client::new();

    let secret = client
        .get("http://localhost:3000/encrypted_secret")
        .header("Authorization", format!("Bearer {}", dummy::BEARER_TOKEN))
        .send()
        .await
        .expect("get request should succeed if server is running")
        .text()
        .await
        .expect("secret response should contain text");

    dummy::CLIENT_KEYPAIR
        .secret_key()
        .decrypt_from(dummy::SERVER_KEYPAIR.public_key(), &secret)
}

async fn set_secret(secret: &str) {
    let encrypted = dummy::CLIENT_KEYPAIR
        .secret_key()
        .encrypt_to(dummy::SERVER_KEYPAIR.public_key(), secret);

    let client = reqwest::Client::new();
    client
        .put("http://localhost:3000/encrypted_secret")
        .body(encrypted)
        .header("Authorization", format!("Bearer {}", dummy::BEARER_TOKEN))
        .send()
        .await
        .expect("put request should succeed if server is running");
}

use http_disaster_poc::dummy;

use http_disaster_poc::encrypt::DecryptFrom as _;
use http_disaster_poc::encrypt::EncryptTo as _;
