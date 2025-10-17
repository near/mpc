use std::sync::Arc;

use tokio::{
    fs::File,
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::Mutex,
};

use crate::{ports::SecretsRepository, types};

const SECRETS_FILE_NAME: &'static str = "secrets.json";

pub struct SharedJsonSecretsStorage<D>(Arc<Mutex<JsonSecretsStorage<D>>>);

impl SharedJsonSecretsStorage<File> {
    pub async fn open_write() -> Self {
        Self(Arc::new(Mutex::new(
            JsonSecretsStorage::<File>::open_write().await,
        )))
    }

    pub async fn open_read() -> Self {
        Self(Arc::new(Mutex::new(
            JsonSecretsStorage::<File>::open_read().await,
        )))
    }
}

pub struct JsonSecretsStorage<D> {
    destination: D,
}

impl JsonSecretsStorage<File> {
    pub async fn open_write() -> Self {
        let destination = File::create_new(SECRETS_FILE_NAME).await.expect("Error");

        Self { destination }
    }

    pub async fn open_read() -> Self {
        let destination = File::open(SECRETS_FILE_NAME).await.expect("Error");

        Self { destination }
    }
}

impl<W> JsonSecretsStorage<W>
where
    W: AsyncWrite + Unpin,
{
    pub async fn store_secrets(&mut self, secrets: &types::PersistentSecrets) {
        let encoded_secrets = serde_json::to_vec(&secrets).expect("TODO");
        (&mut self.destination)
            .write_all(&encoded_secrets)
            .await
            .expect("TODO");
    }
}

impl<R> JsonSecretsStorage<R>
where
    R: AsyncRead + Unpin,
{
    pub async fn load_secrets(&mut self) -> types::PersistentSecrets {
        let mut buffer = Vec::new();
        self.destination
            .read_to_end(&mut buffer)
            .await
            .expect("TODO");

        serde_json::from_slice(&buffer).expect("TODO")
    }
}

impl<D> SecretsRepository for SharedJsonSecretsStorage<D>
where
    D: AsyncRead + Unpin,
    D: AsyncWrite + Unpin,
    D: Send,
{
    type Error = String;

    async fn store_secrets(&self, secrets: &types::PersistentSecrets) -> Result<(), Self::Error> {
        self.0.lock().await.store_secrets(secrets).await;

        Ok(())
    }

    async fn load_secrets(&self) -> Result<types::PersistentSecrets, Self::Error> {
        todo!()
    } // TODO
}

#[cfg(test)]
#[allow(non_snake_case)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[tokio::test]
    async fn json_secrets_storage__should_be_able_to_load_stored_secrets() {
        // Given
        let test_secrets = dummy_persistent_secrets();
        let secrets_storage = shared_vector_storage();

        // When
        secrets_storage
            .store_secrets(&test_secrets)
            .await
            .expect("should work");

        let loaded = secrets_storage.load_secrets().await.expect("should work");

        // Then
        assert_eq!(test_secrets, loaded);
    }

    #[tokio::test]
    async fn storing_secrets_example() {
        let my_generated_secrets = dummy_persistent_secrets();

        let storage = SharedJsonSecretsStorage::<File>::open_write().await;
        storage.store_secrets(&my_generated_secrets);
    }

    fn shared_vector_storage() -> SharedJsonSecretsStorage<Cursor<Vec<u8>>> {
        todo!();
    }

    fn dummy_persistent_secrets() -> types::PersistentSecrets {
        todo!();
    }
}
