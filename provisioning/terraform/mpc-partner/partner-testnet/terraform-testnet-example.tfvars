env        = "testnet"
project_id = "nearone-mpc"
network    = "default"
subnetwork = "default"
image      = "docker.io/nearone/mpc-node-gcp:latest"
region     = "europe-west1"
zone       = "europe-west1-b"
scenario   = "old"
# These will be specific to your node
node_configs = [
  {
    # Each node has a unique account ID
    account   = "signer-c436b5b3-f815-4750-938d-1a4b4b87c911.testnet"
    cipher_pk = "109845d30689abc3b924d93d45347e85afc54b5e6119c76c2f9a0b9c49975fdb"
    # These 3 values below should match your secret names in google secrets manager
    account_sk_secret_id               = "multichain-account-sk-testnet-0"
    cipher_sk_secret_id                = "multichain-cipher-sk-testnet-0"
    sign_sk_secret_id                  = "multichain-sign-sk-testnet-0"
    sk_share_secret_id                 = "multichain-sk-share-testnet-0"
    domain                             = "test.nearone.co"
    gcp_local_encryption_key_secret_id = "multichain-local-encryption-key-0"
    gcp_keyshare_secret_id             = "multichain-sk-share-testnet-0"
    gcp_p2p_private_key_secret_id      = "multichain-sign-sk-testnet-0"
    gcp_account_sk_secret_id           = "multichain-account-sk-testnet-0"
  },
]

# ACCOUNT_ID="$your-account-project"
# DATA_DIR=/home/mpc/data
# GCP_PROJECT_ID="$your-gcp-project" 
# GCP_KEYSHARE_SECRET_ID="multichain-sk-share-testnet-0"
# GCP_LOCAL_ENCRYPTION_KEY_SECRET_ID="multichain-local-encryption-key-0"
# GCP_P2P_PRIVATE_KEY_SECRET_ID="multichain-sign-sk-testnet-0"
# GCP_ACCOUNT_SK_SECRET_ID="multichain-account-sk-testnet-0"
