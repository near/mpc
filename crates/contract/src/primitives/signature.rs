use near_sdk::near;

#[derive(Clone, Debug)]
#[near(serializers=[borsh])]
pub enum SignatureResult<T, E> {
    Ok(T),
    Err(E),
}
