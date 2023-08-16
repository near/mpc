use crate::error::{LeaderNodeError, MpcError};
use crate::key_recovery::get_user_recovery_pk;
use crate::msg::{
    AcceptNodePublicKeysRequest, ClaimOidcNodeRequest, ClaimOidcRequest, ClaimOidcResponse,
    MpcPkRequest, MpcPkResponse, NewAccountRequest, NewAccountResponse, SignNodeRequest,
    SignRequest, SignResponse, UserCredentialsRequest, UserCredentialsResponse,
};
use crate::oauth::OAuthTokenVerifier;
use crate::relayer::msg::RegisterAccountRequest;
use crate::relayer::NearRpcAndRelayerClient;
use crate::transaction::{
    get_create_account_delegate_action, get_local_signed_delegated_action, get_mpc_signature,
    sign_payload_with_mpc, to_dalek_combined_public_key,
};
use crate::{metrics, nar};
use anyhow::Context;
use axum::extract::MatchedPath;
use axum::middleware::{self, Next};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{
    http::{Request, StatusCode},
    routing::post,
    Extension, Json, Router,
};
use axum_extra::extract::WithRejection;
use curv::elliptic::curves::{Ed25519, Point};
use near_crypto::SecretKey;
use near_primitives::delegate_action::NonDelegateAction;
use near_primitives::transaction::{Action, DeleteKeyAction};
use near_primitives::types::AccountId;
use near_primitives::views::FinalExecutionStatus;
use prometheus::{Encoder, TextEncoder};
use rand::{distributions::Alphanumeric, Rng};
use std::net::SocketAddr;
use std::time::Instant;

pub struct Config {
    pub env: String,
    pub port: u16,
    pub sign_nodes: Vec<String>,
    pub near_rpc: String,
    pub relayer_api_key: Option<String>,
    pub relayer_url: String,
    pub near_root_account: String,
    pub account_creator_id: AccountId,
    // TODO: temporary solution
    pub account_creator_sk: SecretKey,
}

pub async fn run<T: OAuthTokenVerifier + 'static>(config: Config) {
    let Config {
        env,
        port,
        sign_nodes,
        near_rpc,
        relayer_api_key,
        relayer_url,
        near_root_account,
        account_creator_id,
        account_creator_sk,
    } = config;
    let _span = tracing::debug_span!("run", env, port);
    tracing::debug!(?sign_nodes, "running a leader node");

    let client = NearRpcAndRelayerClient::connect(&near_rpc, relayer_url, relayer_api_key);
    // FIXME: Internal account id is retrieved from the ID token. We don't have a token for ourselves,
    // but are still forced to allocate allowance.
    // Using randomly generated internal account id ensures the uniqueness of user idenrifier on the relayer side so
    // we can update the allowance on each server run.
    let fake_internal_account_id: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(16)
        .map(char::from)
        .collect();
    client
        .register_account(RegisterAccountRequest {
            account_id: account_creator_id.clone(),
            allowance: 18_000_000_000_000_000_000, // should be enough to create 700_000+ accs
            oauth_token: fake_internal_account_id,
        })
        .await
        .unwrap();

    let state = LeaderState {
        env,
        sign_nodes,
        client,
        reqwest_client: reqwest::Client::new(),
        near_root_account: near_root_account.parse().unwrap(),
        account_creator_id,
        account_creator_sk,
    };

    // Get keys from all sign nodes, and broadcast them out as a set.
    let pk_set = match gather_sign_node_pk_shares(&state).await {
        Ok(pk_set) => pk_set,
        Err(err) => {
            tracing::error!("Unable to gather public keys: {err}");
            return;
        }
    };
    tracing::debug!(?pk_set, "Gathered public keys");
    let messages = match broadcast_pk_set(&state, pk_set).await {
        Ok(messages) => messages,
        Err(err) => {
            tracing::error!("Unable to broadcast public keys: {err}");
            Vec::new()
        }
    };
    tracing::debug!(?messages, "broadcasted public key statuses");

    //TODO: not secure, allow only for testnet, whitelist endpoint etc. for mainnet
    let cors_layer = tower_http::cors::CorsLayer::permissive();

    let app = Router::new()
        // healthcheck endpoint
        .route(
            "/",
            get(|| async move {
                tracing::info!("node is ready to accept connections");
                StatusCode::OK
            }),
        )
        .route("/mpc_public_key", post(mpc_public_key))
        .route("/claim_oidc", post(claim_oidc))
        .route("/user_credentials", post(user_credentials::<T>))
        .route("/new_account", post(new_account::<T>))
        .route("/sign", post(sign::<T>))
        .route("/metrics", get(metrics))
        .route_layer(middleware::from_fn(track_metrics))
        .layer(Extension(state))
        .layer(cors_layer);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    tracing::debug!(?addr, "starting http server");
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

async fn track_metrics<B>(req: Request<B>, next: Next<B>) -> impl IntoResponse {
    let timer = Instant::now();
    let path = if let Some(matched_path) = req.extensions().get::<MatchedPath>() {
        matched_path.as_str().to_owned()
    } else {
        req.uri().path().to_owned()
    };
    let method = req.method().clone();

    let response = next.run(req).await;
    let processing_time = timer.elapsed().as_secs_f64();

    metrics::HTTP_REQUEST_COUNT
        .with_label_values(&[method.as_str(), &path])
        .inc();
    metrics::HTTP_PROCESSING_TIME
        .with_label_values(&[method.as_str(), &path])
        .observe(processing_time);

    if response.status().is_client_error() {
        metrics::HTTP_CLIENT_ERROR_COUNT
            .with_label_values(&[method.as_str(), &path])
            .inc();
    }
    if response.status().is_server_error() {
        metrics::HTTP_SERVER_ERROR_COUNT
            .with_label_values(&[method.as_str(), &path])
            .inc();
    }

    response
}

async fn metrics() -> (StatusCode, String) {
    let grab_metrics = || {
        let encoder = TextEncoder::new();
        let mut buffer = vec![];
        encoder
            .encode(&prometheus::gather(), &mut buffer)
            .with_context(|| "failed to encode metrics")?;

        let response = String::from_utf8(buffer.clone())
            .with_context(|| "failed to convert bytes to string")?;
        buffer.clear();

        Ok::<String, anyhow::Error>(response)
    };

    match grab_metrics() {
        Ok(response) => (StatusCode::OK, response),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to generate prometheus metrics".to_string(),
        ),
    }
}

#[derive(Clone)]
struct LeaderState {
    env: String,
    sign_nodes: Vec<String>,
    client: NearRpcAndRelayerClient,
    reqwest_client: reqwest::Client,
    near_root_account: AccountId,
    account_creator_id: AccountId,
    // TODO: temporary solution
    account_creator_sk: SecretKey,
}

async fn mpc_public_key(
    Extension(state): Extension<LeaderState>,
    WithRejection(Json(_), _): WithRejection<Json<MpcPkRequest>, MpcError>,
) -> (StatusCode, Json<MpcPkResponse>) {
    // Getting MPC PK from sign nodes
    let pk_set = match gather_sign_node_pk_shares(&state).await {
        Ok(pk_set) => pk_set,
        Err(err) => {
            return (
                err.code(),
                Json(MpcPkResponse::Err {
                    msg: err.to_string(),
                }),
            )
        }
    };

    let mpc_pk = match to_dalek_combined_public_key(&pk_set) {
        Ok(mpc_pk) => hex::encode(mpc_pk.to_bytes()),
        Err(err) => {
            return (
                err.code(),
                Json(MpcPkResponse::Err {
                    msg: err.to_string(),
                }),
            )
        }
    };

    (StatusCode::OK, Json(MpcPkResponse::Ok { mpc_pk }))
}

#[tracing::instrument(level = "info", skip_all, fields(env = state.env))]
async fn claim_oidc(
    Extension(state): Extension<LeaderState>,
    WithRejection(Json(claim_oidc_request), _): WithRejection<Json<ClaimOidcRequest>, MpcError>,
) -> (StatusCode, Json<ClaimOidcResponse>) {
    tracing::info!(
        oidc_hash = hex::encode(&claim_oidc_request.oidc_token_hash),
        pk = claim_oidc_request.frp_public_key,
        sig = claim_oidc_request.frp_signature.to_string(),
        "claim_oidc request"
    );

    // Calim OIDC ID Token and get MPC signature from sign nodes
    let sig_share_request = SignNodeRequest::ClaimOidc(ClaimOidcNodeRequest {
        oidc_token_hash: claim_oidc_request.oidc_token_hash,
        public_key: claim_oidc_request.frp_public_key,
        signature: claim_oidc_request.frp_signature,
    });

    let res =
        sign_payload_with_mpc(&state.reqwest_client, &state.sign_nodes, sig_share_request).await;

    match res {
        Ok(mpc_signature) => (
            StatusCode::OK,
            Json(ClaimOidcResponse::Ok { mpc_signature }),
        ),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(ClaimOidcResponse::Err { msg: e.to_string() }),
        ),
    }
}

#[tracing::instrument(level = "info", skip_all, fields(env = state.env))]
async fn user_credentials<T: OAuthTokenVerifier>(
    Extension(state): Extension<LeaderState>,
    WithRejection(Json(request), _): WithRejection<Json<UserCredentialsRequest>, MpcError>,
) -> (StatusCode, Json<UserCredentialsResponse>) {
    tracing::info!(
        oidc_token = format!("{:.5}...", request.oidc_token),
        "user_credentials request"
    );

    match process_user_credentials::<T>(state, request).await {
        Ok(response) => {
            tracing::debug!("responding with OK");
            (StatusCode::OK, Json(response))
        }
        Err(err) => {
            tracing::error!(err = ?err, "failed to process user credentials");
            (
                err.code(),
                Json(UserCredentialsResponse::Err {
                    msg: err.to_string(),
                }),
            )
        }
    }
}

async fn process_user_credentials<T: OAuthTokenVerifier>(
    state: LeaderState,
    request: UserCredentialsRequest,
) -> Result<UserCredentialsResponse, LeaderNodeError> {
    T::verify_token(&request.oidc_token)
        .await
        .map_err(LeaderNodeError::OidcVerificationFailed)?;

    nar::retry(|| async {
        let mpc_user_recovery_pk = get_user_recovery_pk(
            &state.reqwest_client,
            &state.sign_nodes,
            &request.oidc_token,
            request.frp_signature,
            &request.frp_public_key,
        )
        .await?;

        Ok(UserCredentialsResponse::Ok {
            recovery_pk: mpc_user_recovery_pk,
        })
    })
    .await
}

async fn process_new_account<T: OAuthTokenVerifier>(
    state: LeaderState,
    request: NewAccountRequest,
) -> Result<NewAccountResponse, LeaderNodeError> {
    // Create a transaction to create new NEAR account
    let new_user_account_id: AccountId = request
        .near_account_id
        .parse()
        .map_err(|e| LeaderNodeError::MalformedAccountId(request.near_account_id, e))?;
    let oidc_token_claims = T::verify_token(&request.oidc_token)
        .await
        .map_err(LeaderNodeError::OidcVerificationFailed)?;
    let internal_acc_id = oidc_token_claims.get_internal_account_id();

    state
        .client
        .register_account(RegisterAccountRequest {
            account_id: new_user_account_id.clone(),
            allowance: 300_000_000_000_000,
            oauth_token: internal_acc_id.clone(),
        })
        .await?;

    nar::retry(|| async {
        // Get nonce and recent block hash
        let (_hash, block_height, nonce) = state
            .client
            .access_key(
                state.account_creator_id.clone(),
                state.account_creator_sk.public_key(),
            )
            .await
            .map_err(LeaderNodeError::RelayerError)?;

        let mpc_user_recovery_pk = get_user_recovery_pk(
            &state.reqwest_client,
            &state.sign_nodes,
            &request.oidc_token,
            request.user_credentials_frp_signature,
            &request.frp_public_key,
        )
        .await?;

        // Add recovery key to create account options
        let mut new_account_options = request.create_account_options.clone();
        match new_account_options.full_access_keys {
            Some(ref mut keys) => keys.push(mpc_user_recovery_pk.clone()),
            None => new_account_options.full_access_keys = Some(vec![mpc_user_recovery_pk.clone()]),
        }

        let delegate_action = get_create_account_delegate_action(
            &state.account_creator_id,
            &state.account_creator_sk.public_key(),
            &new_user_account_id,
            new_account_options.clone(),
            &state.near_root_account,
            nonce,
            block_height + 100,
        )
        .map_err(LeaderNodeError::Other)?;
        // We create accounts using the local key
        let signed_delegate_action = get_local_signed_delegated_action(
            delegate_action,
            state.account_creator_id.clone(),
            state.account_creator_sk.clone(),
        );

        // Send delegate action to relayer
        let result = state.client.send_meta_tx(signed_delegate_action).await;
        if let Err(err) = &result {
            let err_str = format!("{:?}", err);
            state
                .client
                .invalidate_cache_if_tx_failed(
                    &(
                        state.account_creator_id.clone(),
                        state.account_creator_sk.public_key(),
                    ),
                    &err_str,
                )
                .await;
        }
        let response = result?;

        // TODO: Probably need to check more fields
        if matches!(response.status, FinalExecutionStatus::SuccessValue(_)) {
            Ok(NewAccountResponse::Ok {
                create_account_options: new_account_options,
                user_recovery_public_key: mpc_user_recovery_pk.to_string(),
                near_account_id: new_user_account_id.to_string(),
            })
        } else {
            Err(LeaderNodeError::Other(anyhow::anyhow!(
                "transaction failed with {:?}",
                response.status
            )))
        }
    })
    .await
}

#[tracing::instrument(level = "info", skip_all, fields(env = state.env))]
async fn new_account<T: OAuthTokenVerifier>(
    Extension(state): Extension<LeaderState>,
    WithRejection(Json(request), _): WithRejection<Json<NewAccountRequest>, MpcError>,
) -> (StatusCode, Json<NewAccountResponse>) {
    tracing::info!(
        near_account_id = request.near_account_id.clone(),
        create_account_options = request.create_account_options.to_string(),
        oidc_token = format!("{:.5}...", request.oidc_token),
        "new_account request"
    );

    match process_new_account::<T>(state, request).await {
        Ok(response) => {
            tracing::debug!("responding with OK");
            (StatusCode::OK, Json(response))
        }
        Err(err) => {
            tracing::error!(err = ?err);
            (err.code(), Json(NewAccountResponse::err(err.to_string())))
        }
    }
}

async fn process_sign<T: OAuthTokenVerifier>(
    state: LeaderState,
    request: SignRequest,
) -> Result<SignResponse, LeaderNodeError> {
    // Check OIDC token
    T::verify_token(&request.oidc_token)
        .await
        .map_err(LeaderNodeError::OidcVerificationFailed)?;

    // Prevent recovery key delition
    let requested_delegate_actions: &Vec<NonDelegateAction> = &request.delegate_action.actions;

    let requested_actions: &Vec<Action> = &requested_delegate_actions
        .iter()
        .map(|non_delegate_action| Action::from(non_delegate_action.clone()))
        .collect();

    let delete_key_actions: Vec<&DeleteKeyAction> = requested_actions
        .iter()
        .filter_map(|action| match action {
            Action::DeleteKey(delete_key_action) => Some(delete_key_action),
            _ => None,
        })
        .collect();

    let user_recovery_pk_res = nar::retry::<_, anyhow::Error, _, _>(|| async {
        let mpc_user_recovery_pk = get_user_recovery_pk(
            &state.reqwest_client,
            &state.sign_nodes,
            &request.oidc_token,
            request.user_credentials_frp_signature,
            &request.frp_public_key,
        )
        .await?;

        Ok(mpc_user_recovery_pk)
    })
    .await;

    let user_recovery_pk = user_recovery_pk_res.map_err(|err| {
        tracing::error!("Failed to retrieve recovery pk: {err}");
        LeaderNodeError::FailedToRetrieveRecoveryPk(err)
    })?;

    for delete_key_action in delete_key_actions {
        if delete_key_action.public_key == user_recovery_pk {
            tracing::error!(
                "Recovery key can not be deleted: {:?}",
                delete_key_action.public_key
            );
            Err(LeaderNodeError::RecoveryKeyCanNotBeDeleted(
                delete_key_action.public_key.clone(),
            ))?;
        }
    }

    // Get MPC signature
    nar::retry(|| async {
        let signature = get_mpc_signature(
            &state.reqwest_client,
            &state.sign_nodes,
            &request.oidc_token,
            request.delegate_action.clone(),
            request.frp_signature,
            &request.frp_public_key,
        )
        .await?;

        Ok(SignResponse::Ok { signature })
    })
    .await
}

#[tracing::instrument(level = "info", skip_all, fields(env = state.env))]
async fn sign<T: OAuthTokenVerifier>(
    Extension(state): Extension<LeaderState>,
    WithRejection(Json(request), _): WithRejection<Json<SignRequest>, MpcError>,
) -> (StatusCode, Json<SignResponse>) {
    tracing::info!(
        oidc_token = format!("{:.5}...", request.oidc_token),
        "sign request"
    );

    match process_sign::<T>(state, request).await {
        Ok(response) => {
            tracing::debug!("responding with OK");
            (StatusCode::OK, Json(response))
        }
        Err(e) => {
            tracing::error!(err = ?e);
            (e.code(), Json(SignResponse::err(e.to_string())))
        }
    }
}

async fn gather_sign_node_pk_shares(
    state: &LeaderState,
) -> Result<Vec<Point<Ed25519>>, LeaderNodeError> {
    let fut = nar::retry_every(std::time::Duration::from_secs(1), || async {
        let mut results: Vec<(usize, Point<Ed25519>)> = crate::transaction::call_all_nodes(
            &state.reqwest_client,
            &state.sign_nodes,
            "public_key_node",
            (),
        )
        .await
        .map_err(|err| {
            tracing::debug!("failed to gather pk: {err:?}");
            err
        })?;

        results.sort_by_key(|(index, _)| *index);
        let results: Vec<Point<Ed25519>> =
            results.into_iter().map(|(_index, point)| point).collect();

        Result::<Vec<Point<Ed25519>>, LeaderNodeError>::Ok(results)
    });

    let results = tokio::time::timeout(std::time::Duration::from_secs(60), fut)
        .await
        .map_err(|_| LeaderNodeError::TimeoutGatheringPublicKeys)??;
    Ok(results)
}

async fn broadcast_pk_set(
    state: &LeaderState,
    pk_set: Vec<Point<Ed25519>>,
) -> anyhow::Result<Vec<String>> {
    let request = AcceptNodePublicKeysRequest {
        public_keys: pk_set,
    };

    let messages: Vec<String> = crate::transaction::call_all_nodes(
        &state.reqwest_client,
        &state.sign_nodes,
        "accept_pk_set",
        request,
    )
    .await?;

    Ok(messages)
}
