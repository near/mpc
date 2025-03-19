use super::{KeyshareStorage, PartialRootKeyshareData, RootKeyshareData};
use crate::keyshare::migration::try_load_from_old_keyshare;
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
    async fn load(&self) -> anyhow::Result<Option<PartialRootKeyshareData>> {
        let secret_name = format!("projects/{}/secrets/{}", self.project_id, self.secret_id);
        let versions = self
            .secrets_client
            .get()
            .list_secret_versions(ListSecretVersionsRequest {
                parent: secret_name,
                ..Default::default()
            })
            .await
            .context("Failed to list secret versions")?
            .into_inner();

        let Some(latest_version) = versions
            .versions
            .into_iter()
            .find(|version| version.state() == State::Enabled)
        else {
            return Ok(None);
        };
        let secret = self
            .secrets_client
            .get()
            .access_secret_version(AccessSecretVersionRequest {
                name: latest_version.name,
            })
            .await
            .context("Failed to access secret version")?
            .into_inner()
            .payload
            .ok_or_else(|| anyhow::anyhow!("Secret version has no payload"))?;

        let data = secret.data.as_sensitive_bytes();
        let keyshare = match try_load_from_old_keyshare(data) {
            None => serde_json::from_slice(data).context("Failed to parse keygen")?,
            Some(old_keyshare) => old_keyshare,
        };
        Ok(Some(keyshare))
    }

    async fn store(&self, root_keyshare: &RootKeyshareData) -> anyhow::Result<()> {
        let existing = self.load().await.context("Checking existing keyshare")?;
        if let Some(existing) = existing {
            RootKeyshareData::compare_against_existing_share(root_keyshare, &existing)?;
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
