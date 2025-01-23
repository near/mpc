#!/bin/bash
# This script is intended to be used for running nearone/mpc in a GCP environment where
# near/mpc was previously running.

# GCP_PROJECT_ID: the project name (used to fetch secrets below).
# Same as MPC_GCP_PROJECT_ID in the near/mpc deployment.
echo Using GCP_PROJECT_ID=${GCP_PROJECT_ID:?"GCP_PROJECT_ID is required"}
# GCP_KEYSHARE_SECRET_ID: the secret id for the root keyshare.
# Same as MPC_SK_SHARE_SECRET_ID in the near/mpc deployment.
echo Using GCP_KEYSHARE_SECRET_ID=${GCP_KEYSHARE_SECRET_ID:?"GCP_KEYSHARE_SECRET_ID is required"}
# GCP_LOCAL_ENCRYPTION_KEY_SECRET_ID: asymmetric AES key for local DB encryption.
# **This is a new secret**. Prior to running nearone/mpc, you need to create this
# secret to be any random 16 bytes, hex-encoded as a 32 character string. This is
# used to encrypt the local database containing triples and presignatures.
echo Using GCP_LOCAL_ENCRYPTION_KEY_SECRET_ID=${GCP_LOCAL_ENCRYPTION_KEY_SECRET_ID:?"GCP_LOCAL_ENCRYPTION_KEY_SECRET_ID is required"}
# GCP_P2P_PRIVATE_KEY_SECRET_ID: the secret id for the P2P private key.
# nearone/mpc uses TLS instead of custom encryption for mesh communication.
# Therefore, only one key is needed rather than two before.
# The previous GCP secret ID whose value would be passed to MPC_SIGN_SK for
# the near/mpc binary should be passed in here. The secret's payload should
# be a private key in the format of ed25519:<base58 encoded private key>.
echo Using GCP_P2P_PRIVATE_KEY_SECRET_ID=${GCP_P2P_PRIVATE_KEY_SECRET_ID:?"GCP_P2P_PRIVATE_KEY_SECRET_ID is required"}
# GCP_ACCOUNT_SK_SECRET_ID: the secret id for the Near account secret key.
# The previous GCP secret ID whose value would be passed to MPC_ACCOUNT_SK
# for the near/mpc binary should be passed in here. The secret's payload should
# be a private key in the format of ed25519:<base58 encoded private key>.
echo Using GCP_ACCOUNT_SK_SECRET_ID=${GCP_ACCOUNT_SK_SECRET_ID:?"GCP_ACCOUNT_SK_SECRET_ID is required"}

# Note that other non-secret configurations are passed in config.yaml.

echo "Fetching local encryption key from GCP secret manager..."
LOCAL_ENCRYPTION_KEY=$(gcloud secrets versions access latest --project $GCP_PROJECT_ID --secret=$GCP_LOCAL_ENCRYPTION_KEY_SECRET_ID)
echo "Fetching P2P private key from GCP secret manager..."
P2P_PRIVATE_KEY=$(gcloud secrets versions access latest --project $GCP_PROJECT_ID --secret=$GCP_P2P_PRIVATE_KEY_SECRET_ID)
echo "Fetching account secret key from GCP secret manager..."
ACCOUNT_SK=$(gcloud secrets versions access latest --project $GCP_PROJECT_ID --secret=$GCP_ACCOUNT_SK_SECRET_ID)

echo "Starting mpc node..."
GCP_PROJECT_ID="${GCP_PROJECT_ID}" \
GCP_KEYSHARE_SECRET_ID="${GCP_KEYSHARE_SECRET_ID}" \
MPC_SECRET_STORE_KEY=${LOCAL_ENCRYPTION_KEY} \
MPC_P2P_PRIVATE_KEY=${P2P_PRIVATE_KEY} \
MPC_ACCOUNT_SK=${ACCOUNT_SK} \
/app/mpc-node start
