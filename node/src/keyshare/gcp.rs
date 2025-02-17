use super::{KeyshareStorage, RootKeyshareData};
use anyhow::Context;
use gcloud_sdk::google::cloud::secretmanager::v1::secret_manager_service_client::SecretManagerServiceClient;
use gcloud_sdk::google::cloud::secretmanager::v1::secret_version::State;
use gcloud_sdk::google::cloud::secretmanager::v1::{
    AccessSecretVersionRequest, AddSecretVersionRequest, ListSecretVersionsRequest,
};
use gcloud_sdk::proto_ext::secretmanager::SecretPayload;
use gcloud_sdk::{GoogleApi, GoogleAuthMiddleware, SecretValue};

/// Keyshare storage that loads and stores the key from Google Secret Manager.
pub struct GcpKeyshareStorage {
    secrets_client: GoogleApi<SecretManagerServiceClient<GoogleAuthMiddleware>>,
    project_id: String,
    secret_id: String,
}

impl GcpKeyshareStorage {
    pub async fn new(project_id: String, secret_id: String) -> anyhow::Result<Self> {
        let secrets_client = GoogleApi::from_function(
            SecretManagerServiceClient::new,
            "https://secretmanager.googleapis.com",
            None,
        )
        .await
        .context("Failed to create SecretManagerServiceClient")?;

        Ok(Self {
            secrets_client,
            project_id,
            secret_id,
        })
    }
}

#[async_trait::async_trait]
impl KeyshareStorage for GcpKeyshareStorage {
    async fn load(&self) -> anyhow::Result<Option<RootKeyshareData>> {
        let secret_name = format!(
            "projects/{}/secrets/{}/versions/latest",
            self.project_id, self.secret_id
        );

        let result = self
            .secrets_client
            .get()
            .access_secret_version(AccessSecretVersionRequest { name: secret_name })
            .await;

        let secret = result
            .context("Failed to access secret version")?
            .into_inner()
            .payload
            .ok_or_else(|| anyhow::anyhow!("Secret version has no payload"))?;

        let keyshare: RootKeyshareData = serde_json::from_slice(secret.data.as_sensitive_bytes())
            .context("Failed to parse keygen")?;
        Ok(Some(keyshare))
    }

    async fn store(&self, root_keyshare: &RootKeyshareData) -> anyhow::Result<()> {
        let existing = self.load().await.context("Checking existing keyshare")?;
        if let Some(existing) = existing {
            if existing.epoch >= root_keyshare.epoch {
                return Err(anyhow::anyhow!(
                    "Refusing to overwrite existing keyshare of epoch {} with new keyshare of older epoch {}",
                    existing.epoch,
                    root_keyshare.epoch,
                ));
            }
        }
        let secret_name = format!("projects/{}/secrets/{}", self.project_id, self.secret_id);
        let data = serde_json::to_vec(&root_keyshare).context("Failed to serialize keygen")?;
        self.secrets_client
            .get()
            .add_secret_version(AddSecretVersionRequest {
                parent: secret_name,
                payload: Some(SecretPayload {
                    data: SecretValue::new(data),
                    ..Default::default()
                }),
            })
            .await
            .context("Failed to create secret version")?;
        Ok(())
    }
}
