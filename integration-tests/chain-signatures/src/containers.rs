use super::{local::NodeConfig, utils, MultichainConfig};
use anyhow::{anyhow, Context};
use async_process::Child;
use bollard::exec::CreateExecOptions;
use bollard::{container::LogsOptions, network::CreateNetworkOptions, service::Ipam, Docker};
use futures::{lock::Mutex, StreamExt};
use mpc_keys::hpke;
use near_workspaces::AccountId;
use once_cell::sync::Lazy;
use serde_json::json;
use testcontainers::clients::Cli;
use testcontainers::core::Port;
use testcontainers::Image;
use testcontainers::{
    core::{ExecCommand, WaitFor},
    Container, GenericImage, RunnableImage,
};
use tokio::io::AsyncWriteExt;
use tracing;

static NETWORK_MUTEX: Lazy<Mutex<i32>> = Lazy::new(|| Mutex::new(0));

pub struct Node<'a> {
    pub container: Container<'a, GenericImage>,
    pub address: String,
    pub account_id: AccountId,
    pub account_sk: near_workspaces::types::SecretKey,
    pub local_address: String,
    pub cipher_pk: hpke::PublicKey,
    pub cipher_sk: hpke::SecretKey,
    pub sign_pk: near_workspaces::types::PublicKey,
    cfg: MultichainConfig,
}

impl<'a> Node<'a> {
    // Container port used for the docker network, does not have to be unique
    const CONTAINER_PORT: u16 = 3000;

    pub async fn run(
        ctx: &super::Context<'a>,
        account_id: &AccountId,
        account_sk: &near_workspaces::types::SecretKey,
        cfg: &MultichainConfig,
    ) -> anyhow::Result<Node<'a>> {
        tracing::info!("running node container, account_id={}", account_id);
        let (cipher_sk, cipher_pk) = hpke::generate();
        let sign_sk =
            near_crypto::SecretKey::from_seed(near_crypto::KeyType::ED25519, "integration-test");
        let sign_pk = sign_sk.public_key();
        let storage_options = ctx.storage_options.clone();
        // Use proxied address to mock slow, congested or unstable rpc connection
        let near_rpc = ctx.lake_indexer.rpc_host_address_proxied.clone();
        let mpc_contract_id = ctx.mpc_contract.id().clone();
        let indexer_options = mpc_recovery_node::indexer::Options {
            s3_bucket: ctx.localstack.s3_bucket.clone(),
            s3_region: ctx.localstack.s3_region.clone(),
            s3_url: Some(ctx.localstack.s3_host_address.clone()),
            start_block_height: 0,
        };
        let args = mpc_recovery_node::cli::Cli::Start {
            near_rpc: near_rpc.clone(),
            light_client_addr: ctx.light_client.address.clone(),
            mpc_contract_id: mpc_contract_id.clone(),
            account_id: account_id.clone(),
            account_sk: account_sk.to_string().parse()?,
            web_port: Self::CONTAINER_PORT,
            cipher_pk: hex::encode(cipher_pk.to_bytes()),
            cipher_sk: hex::encode(cipher_sk.to_bytes()),
            sign_sk: Some(sign_sk),
            indexer_options: indexer_options.clone(),
            my_address: None,
            storage_options: storage_options.clone(),
            min_triples: cfg.triple_cfg.min_triples,
            max_triples: cfg.triple_cfg.max_triples,
            max_concurrent_introduction: cfg.triple_cfg.max_concurrent_introduction,
            max_concurrent_generation: cfg.triple_cfg.max_concurrent_generation,
            min_presignatures: cfg.presig_cfg.min_presignatures,
            max_presignatures: cfg.presig_cfg.max_presignatures,
        }
        .into_str_args();
        let image: GenericImage = GenericImage::new("near/mpc-recovery-node", "latest")
            .with_wait_for(WaitFor::Nothing)
            .with_exposed_port(Self::CONTAINER_PORT)
            .with_env_var("RUST_LOG", "mpc_recovery_node=DEBUG")
            .with_env_var("RUST_BACKTRACE", "1");
        let image: RunnableImage<GenericImage> = (image, args).into();
        let image = image.with_network(&ctx.docker_network);
        let container = ctx.docker_client.cli.run(image);
        let ip_address = ctx
            .docker_client
            .get_network_ip_address(&container, &ctx.docker_network)
            .await?;
        let host_port = container.get_host_port_ipv4(Self::CONTAINER_PORT);

        container.exec(ExecCommand {
            cmd: format!("bash -c 'while [[ \"$(curl -s -o /dev/null -w ''%{{http_code}}'' localhost:{})\" != \"200\" ]]; do sleep 1; done'", Self::CONTAINER_PORT),
            ready_conditions: vec![WaitFor::message_on_stdout("node is ready to accept connections")]
        });

        let full_address = format!("http://{ip_address}:{}", Self::CONTAINER_PORT);
        tracing::info!(
            full_address,
            "node container is running, account_id={}",
            account_id
        );
        Ok(Node {
            container,
            address: full_address,
            account_id: account_id.clone(),
            account_sk: account_sk.clone(),
            local_address: format!("http://localhost:{host_port}"),
            cipher_pk,
            cipher_sk,
            sign_pk: sign_pk.to_string().parse()?,
            cfg: cfg.clone(),
        })
    }

    pub fn kill(&self) -> NodeConfig {
        self.container.stop();
        NodeConfig {
            web_port: Self::CONTAINER_PORT,
            account_id: self.account_id.clone(),
            account_sk: self.account_sk.clone(),
            cipher_pk: self.cipher_pk.clone(),
            cipher_sk: self.cipher_sk.clone(),
            cfg: self.cfg.clone(),
        }
    }

    pub async fn restart(ctx: &super::Context<'a>, config: NodeConfig) -> anyhow::Result<Self> {
        let cipher_pk = config.cipher_pk;
        let cipher_sk = config.cipher_sk;
        let cfg = config.cfg;
        let account_id = config.account_id;
        let account_sk = config.account_sk;
        let storage_options = ctx.storage_options.clone();
        let near_rpc = ctx.lake_indexer.rpc_host_address_proxied.clone();
        let mpc_contract_id = ctx.mpc_contract.id().clone();
        let indexer_options = mpc_recovery_node::indexer::Options {
            s3_bucket: ctx.localstack.s3_bucket.clone(),
            s3_region: ctx.localstack.s3_region.clone(),
            s3_url: Some(ctx.localstack.s3_host_address.clone()),
            start_block_height: 0,
        };
        let sign_sk =
            near_crypto::SecretKey::from_seed(near_crypto::KeyType::ED25519, "integration-test");
        let args = mpc_recovery_node::cli::Cli::Start {
            near_rpc: near_rpc.clone(),
            light_client_addr: ctx.light_client.address.clone(),
            mpc_contract_id: mpc_contract_id.clone(),
            account_id: account_id.clone(),
            account_sk: account_sk.to_string().parse()?,
            web_port: Self::CONTAINER_PORT,
            cipher_pk: hex::encode(cipher_pk.to_bytes()),
            cipher_sk: hex::encode(cipher_sk.to_bytes()),
            indexer_options: indexer_options.clone(),
            my_address: None,
            storage_options: storage_options.clone(),
            min_triples: cfg.triple_cfg.min_triples,
            max_triples: cfg.triple_cfg.max_triples,
            max_concurrent_introduction: cfg.triple_cfg.max_concurrent_introduction,
            max_concurrent_generation: cfg.triple_cfg.max_concurrent_generation,
            min_presignatures: cfg.presig_cfg.min_presignatures,
            max_presignatures: cfg.presig_cfg.max_presignatures,
            sign_sk: Some(sign_sk),
        }
        .into_str_args();
        let image: GenericImage = GenericImage::new("near/mpc-recovery-node", "latest")
            .with_wait_for(WaitFor::Nothing)
            .with_exposed_port(Self::CONTAINER_PORT)
            .with_env_var("RUST_LOG", "mpc_recovery_node=DEBUG")
            .with_env_var("RUST_BACKTRACE", "1");
        let image: RunnableImage<GenericImage> = (image, args).into();
        let image = image.with_network(&ctx.docker_network);
        let container = ctx.docker_client.cli.run(image);
        let ip_address = ctx
            .docker_client
            .get_network_ip_address(&container, &ctx.docker_network)
            .await?;
        let host_port = container.get_host_port_ipv4(Self::CONTAINER_PORT);

        container.exec(ExecCommand {
            cmd: format!("bash -c 'while [[ \"$(curl -s -o /dev/null -w ''%{{http_code}}'' localhost:{})\" != \"200\" ]]; do sleep 1; done'", Self::CONTAINER_PORT),
            ready_conditions: vec![WaitFor::message_on_stdout("node is ready to accept connections")]
        });

        let full_address = format!("http://{ip_address}:{}", Self::CONTAINER_PORT);
        tracing::info!(
            full_address,
            "node container is running, account_id={}",
            account_id
        );
        Ok(Node {
            container,
            address: full_address,
            account_id: account_id.clone(),
            account_sk: account_sk.clone(),
            local_address: format!("http://localhost:{host_port}"),
            cipher_pk,
            cipher_sk,
            sign_pk: account_sk.public_key(),
            cfg: cfg.clone(),
        })
    }
}

pub struct LocalStack<'a> {
    pub container: Container<'a, GenericImage>,
    pub address: String,
    pub s3_address: String,
    pub s3_host_address: String,
    pub s3_bucket: String,
    pub s3_region: String,
}

impl<'a> LocalStack<'a> {
    const S3_CONTAINER_PORT: u16 = 4566;

    pub async fn run(
        docker_client: &'a DockerClient,
        network: &str,
        s3_bucket: String,
        s3_region: String,
    ) -> anyhow::Result<LocalStack<'a>> {
        tracing::info!("running LocalStack container...");
        let image = GenericImage::new("localstack/localstack", "3.0.0")
            .with_wait_for(WaitFor::message_on_stdout("Running on"));
        let image: RunnableImage<GenericImage> = image.into();
        let image = image.with_network(network);
        let container = docker_client.cli.run(image);
        let address = docker_client
            .get_network_ip_address(&container, network)
            .await?;

        // Create the bucket
        let create_result = docker_client
            .docker
            .create_exec(
                container.id(),
                CreateExecOptions::<&str> {
                    attach_stdout: Some(true),
                    attach_stderr: Some(true),
                    cmd: Some(vec![
                        "awslocal",
                        "s3api",
                        "create-bucket",
                        "--bucket",
                        &s3_bucket,
                        "--region",
                        &s3_region,
                    ]),
                    ..Default::default()
                },
            )
            .await?;
        docker_client
            .docker
            .start_exec(&create_result.id, None)
            .await?;

        let s3_address = format!("http://{}:{}", address, Self::S3_CONTAINER_PORT);
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        let s3_host_address = {
            let s3_host_port = container.get_host_port_ipv4(Self::S3_CONTAINER_PORT);
            format!("http://127.0.0.1:{s3_host_port}")
        };
        #[cfg(target_arch = "x86_64")]
        let s3_host_address = {
            let s3_host_port = container.get_host_port_ipv6(Self::S3_CONTAINER_PORT);
            format!("http://[::1]:{s3_host_port}")
        };

        tracing::info!(
            s3_address,
            s3_host_address,
            "LocalStack container is running"
        );
        Ok(LocalStack {
            container,
            address,
            s3_address,
            s3_host_address,
            s3_bucket,
            s3_region,
        })
    }
}

pub struct LakeIndexer<'a> {
    pub container: Container<'a, GenericImage>,
    pub bucket_name: String,
    pub region: String,
    pub rpc_address: String,
    pub rpc_host_address: String,
    pub rpc_host_address_proxied: String,
    // Toxi Server is only used in network traffic originated from Lake Indexer
    // to simulate high load and slowness etc. in Lake Indexer
    // Child process is used for proxy host (local node) to container
    pub toxi_server_process: Child,
    // Container toxi server is used for proxy container to container
    pub toxi_server_container: Container<'a, GenericImage>,
}

impl<'a> LakeIndexer<'a> {
    pub const CONTAINER_RPC_PORT: u16 = 3030;

    pub const S3_PORT_PROXIED: u16 = 4566;
    pub const S3_ADDRESS_PROXIED: &'static str = "127.0.0.1:4566";
    pub const TOXI_SERVER_PROCESS_PORT: u16 = 8474;
    pub const TOXI_SERVER_EXPOSE_PORT: u16 = 8475;
    pub const TOXI_SERVER_PROCESS_ADDRESS: &'static str = "http://127.0.0.1:8474";
    pub const TOXI_SERVER_EXPOSE_ADDRESS: &'static str = "http://127.0.0.1:8475";

    async fn spin_up_toxi_server_process() -> anyhow::Result<Child> {
        let toxi_server = async_process::Command::new("toxiproxy-server")
            .kill_on_drop(true)
            .spawn()
            .with_context(|| "failed to run toxiproxy-server")?;
        utils::ping_until_ok(
            &format!("{}/version", Self::TOXI_SERVER_PROCESS_ADDRESS),
            10,
        )
        .await?;
        Ok(toxi_server)
    }

    async fn spin_up_toxi_server_container(
        docker_client: &'a DockerClient,
        network: &str,
    ) -> anyhow::Result<Container<'a, GenericImage>> {
        let image = GenericImage::new("ghcr.io/shopify/toxiproxy", "2.9.0")
            .with_exposed_port(Self::CONTAINER_RPC_PORT);
        let image: RunnableImage<GenericImage> = image.into();
        let image = image.with_network(network).with_mapped_port(Port {
            local: Self::TOXI_SERVER_EXPOSE_PORT,
            internal: Self::TOXI_SERVER_PROCESS_PORT,
        });
        let container = docker_client.cli.run(image);
        container.exec(ExecCommand {
            cmd: format!("bash -c 'while [[ \"$(curl -s -o /dev/null -w ''%{{http_code}}'' localhost:{}/version)\" != \"200\" ]]; do sleep 1; done'", Self::TOXI_SERVER_PROCESS_PORT),
            ready_conditions: vec![WaitFor::message_on_stdout("version")]
        });

        Ok(container)
    }

    // Populate a new proxy in toxi proxy server. It proxies all traffic originated from `listen`
    // to `upstream`. The proxy can be configured later (adding latency etc.) given the `name`
    // `listen` and `upstream` must in format `host:port` since toxiproxy operates on tcp level
    // host = true, proxy between a host client request host/container server
    // host = false, proxy between a container client to a container server
    // With current docker setup, container client cannot request host server
    async fn populate_proxy(
        name: &str,
        host: bool,
        listen: &str,
        upstream: &str,
    ) -> anyhow::Result<()> {
        let toxiproxy_client = reqwest::Client::default();
        let proxies = json!([{
            "name": name,
            "listen": listen,
            "upstream": upstream
        }]);
        let proxies_json = serde_json::to_string(&proxies).unwrap();
        toxiproxy_client
            .post(format!(
                "{}/populate",
                if host {
                    Self::TOXI_SERVER_PROCESS_ADDRESS
                } else {
                    Self::TOXI_SERVER_EXPOSE_ADDRESS
                }
            ))
            .header("Content-Type", "application/json")
            .body(proxies_json)
            .send()
            .await?;
        Ok(())
    }

    pub async fn run(
        docker_client: &'a DockerClient,
        network: &str,
        s3_address: &str,
        bucket_name: String,
        region: String,
    ) -> anyhow::Result<LakeIndexer<'a>> {
        tracing::info!("initializing toxi proxy servers");
        let toxi_server_process = Self::spin_up_toxi_server_process().await?;
        let toxi_server_container =
            Self::spin_up_toxi_server_container(docker_client, network).await?;
        let s3_address_without_http = &s3_address[7..];
        let toxi_server_container_address = docker_client
            .get_network_ip_address(&toxi_server_container, network)
            .await?;
        let s3_address_proxied = format!(
            "{}:{}",
            &toxi_server_container_address,
            Self::S3_PORT_PROXIED
        );
        tracing::info!(
            s3_address,
            s3_address_proxied,
            "Proxy S3 access from Lake Indexer"
        );
        Self::populate_proxy(
            "lake-s3",
            false,
            &s3_address_proxied,
            s3_address_without_http,
        )
        .await?;

        tracing::info!(
            network,
            s3_address_proxied,
            bucket_name,
            region,
            "running NEAR Lake Indexer container..."
        );

        let image = GenericImage::new("ghcr.io/near/near-lake-indexer", "node-1.38")
            .with_env_var("AWS_ACCESS_KEY_ID", "FAKE_LOCALSTACK_KEY_ID")
            .with_env_var("AWS_SECRET_ACCESS_KEY", "FAKE_LOCALSTACK_ACCESS_KEY")
            .with_wait_for(WaitFor::message_on_stderr("Starting Streamer"))
            .with_exposed_port(Self::CONTAINER_RPC_PORT);
        let image: RunnableImage<GenericImage> = (
            image,
            vec![
                "--endpoint".to_string(),
                format!("http://{}", s3_address_proxied),
                "--bucket".to_string(),
                bucket_name.clone(),
                "--region".to_string(),
                region.clone(),
                "--stream-while-syncing".to_string(),
                "sync-from-latest".to_string(),
            ],
        )
            .into();
        let image = image.with_network(network);
        let container = docker_client.cli.run(image);
        let address = docker_client
            .get_network_ip_address(&container, network)
            .await?;
        let rpc_address = format!("http://{}:{}", address, Self::CONTAINER_RPC_PORT);
        let rpc_host_port = container.get_host_port_ipv4(Self::CONTAINER_RPC_PORT);
        let rpc_host_address = format!("http://127.0.0.1:{rpc_host_port}");
        let rpc_port_proxied = utils::pick_unused_port().await?;
        let rpc_host_address_proxied = format!("http://127.0.0.1:{rpc_port_proxied}");

        tracing::info!(
            "Proxy Indexer's RPC address from {} to {}",
            rpc_host_address,
            rpc_host_address_proxied
        );
        Self::populate_proxy(
            "lake-rpc",
            true,
            &format!("127.0.0.1:{}", rpc_port_proxied),
            &format!("127.0.0.1:{}", rpc_host_port),
        )
        .await?;

        tracing::info!(
            bucket_name,
            region,
            rpc_address,
            rpc_host_address,
            rpc_host_address_proxied,
            "NEAR Lake Indexer container is running"
        );
        Ok(LakeIndexer {
            container,
            bucket_name,
            region,
            rpc_address,
            rpc_host_address,
            rpc_host_address_proxied,
            toxi_server_process,
            toxi_server_container,
        })
    }
}

pub struct LightClient<'a> {
    pub container: Container<'a, GenericImage>,
    pub bucket_name: String, // TODO: Do we need this?
    pub region: String,      // TODO: Do we need this?
    pub address: String,
    pub host_address: String,
    // TODO: any additional fields?
}

impl<'a> LightClient<'a> {
    pub const CONTAINER_RPC_PORT: u16 = 3031; // TODO: is this port ok?

    pub async fn run(
        docker_client: &'a DockerClient,
        network: &str,
        bucket_name: String,
        region: String,
    ) -> anyhow::Result<LightClient<'a>> {
        tracing::info!(
            network,
            bucket_name,
            region,
            "running LightClient container..."
        );

        let image = GenericImage::new(
            "ghcr.io/near/near-light-client/light-client",
            "f4ce326d9c2a6728e8bc39b4d8720f81be87dc43",
        ) // TODO: deploy and update docker image version
        // .with_env_var("AWS_ACCESS_KEY_ID", "FAKE_LOCALSTACK_KEY_ID") // Replace with LightCLient specific env vars if any
        // .with_env_var("AWS_SECRET_ACCESS_KEY", "FAKE_LOCALSTACK_ACCESS_KEY")
        .with_wait_for(WaitFor::message_on_stderr("Starting Streamer")) // TODO: replace with message from LightClient
        .with_exposed_port(Self::CONTAINER_RPC_PORT);
        let image: RunnableImage<GenericImage> = (
            image,
            vec![
                "--bucket".to_string(), // TODO: check if we need these args, what args do we need?
                bucket_name.clone(),
                "--region".to_string(),
                region.clone(),
                "--stream-while-syncing".to_string(),
                "sync-from-latest".to_string(),
            ],
        )
            .into();
        let image = image.with_network(network);
        let container = docker_client.cli.run(image);
        let address = docker_client
            .get_network_ip_address(&container, network)
            .await?;

        // TODO: check address and host_port, is it what we need?
        let address = format!("http://{}:{}", address, Self::CONTAINER_RPC_PORT);
        let host_port = container.get_host_port_ipv4(Self::CONTAINER_RPC_PORT);
        let host_address = format!("http://127.0.0.1:{host_port}");

        tracing::info!(
            bucket_name,
            region,
            address,
            host_address,
            "NEAR Lake Indexer container is running"
        );
        Ok(LightClient {
            container,
            bucket_name,
            region,
            address,
            host_address,
        })
    }
}

pub struct DockerClient {
    pub docker: Docker,
    pub cli: Cli,
}

impl DockerClient {
    pub async fn get_network_ip_address<I: Image>(
        &self,
        container: &Container<'_, I>,
        network: &str,
    ) -> anyhow::Result<String> {
        let network_settings = self
            .docker
            .inspect_container(container.id(), None)
            .await?
            .network_settings
            .ok_or_else(|| anyhow!("missing NetworkSettings on container '{}'", container.id()))?;
        let ip_address = network_settings
            .networks
            .ok_or_else(|| {
                anyhow!(
                    "missing NetworkSettings.Networks on container '{}'",
                    container.id()
                )
            })?
            .get(network)
            .cloned()
            .ok_or_else(|| {
                anyhow!(
                    "container '{}' is not a part of network '{}'",
                    container.id(),
                    network
                )
            })?
            .ip_address
            .ok_or_else(|| {
                anyhow!(
                    "container '{}' belongs to network '{}', but is not assigned an IP address",
                    container.id(),
                    network
                )
            })?;

        Ok(ip_address)
    }

    pub async fn create_network(&self, network: &str) -> anyhow::Result<()> {
        let _lock = &NETWORK_MUTEX.lock().await;
        let list = self.docker.list_networks::<&str>(None).await?;
        if list.iter().any(|n| n.name == Some(network.to_string())) {
            return Ok(());
        }

        let create_network_options = CreateNetworkOptions {
            name: network,
            check_duplicate: true,
            driver: if cfg!(windows) {
                "transparent"
            } else {
                "bridge"
            },
            ipam: Ipam {
                config: None,
                ..Default::default()
            },
            ..Default::default()
        };
        let _response = &self.docker.create_network(create_network_options).await?;

        Ok(())
    }

    pub async fn continuously_print_logs(&self, id: &str) -> anyhow::Result<()> {
        let mut output = self.docker.logs::<String>(
            id,
            Some(LogsOptions {
                follow: true,
                stdout: true,
                stderr: true,
                ..Default::default()
            }),
        );

        // Asynchronous process that pipes docker attach output into stdout.
        // Will die automatically once Docker container output is closed.
        tokio::spawn(async move {
            let mut stdout = tokio::io::stdout();

            while let Some(Ok(output)) = output.next().await {
                stdout
                    .write_all(output.into_bytes().as_ref())
                    .await
                    .unwrap();
                stdout.flush().await.unwrap();
            }
        });

        Ok(())
    }
}

impl Default for DockerClient {
    fn default() -> Self {
        Self {
            docker: Docker::connect_with_local(
                "unix:///var/run/docker.sock",
                // 10 minutes timeout for all requests in case a lot of tests are being ran in parallel.
                600,
                bollard::API_DEFAULT_VERSION,
            )
            .unwrap(),
            cli: Default::default(),
        }
    }
}

pub struct Datastore<'a> {
    pub container: Container<'a, GenericImage>,
    pub address: String,
    pub local_address: String,
}

impl<'a> Datastore<'a> {
    pub const CONTAINER_PORT: u16 = 3000;

    pub async fn run(
        docker_client: &'a DockerClient,
        network: &str,
        project_id: &str,
    ) -> anyhow::Result<Datastore<'a>> {
        tracing::info!("Running datastore container...");
        let image = GenericImage::new(
            "gcr.io/google.com/cloudsdktool/google-cloud-cli",
            "464.0.0-emulators",
        )
        .with_wait_for(WaitFor::message_on_stderr("Dev App Server is now running."))
        .with_exposed_port(Self::CONTAINER_PORT)
        .with_entrypoint("gcloud")
        .with_env_var(
            "DATASTORE_EMULATOR_HOST",
            format!("0.0.0.0:{}", Self::CONTAINER_PORT),
        )
        .with_env_var("DATASTORE_PROJECT_ID", project_id);
        let image: RunnableImage<GenericImage> = (
            image,
            vec![
                "beta".to_string(),
                "emulators".to_string(),
                "datastore".to_string(),
                "start".to_string(),
                format!("--project={project_id}"),
                "--host-port".to_string(),
                format!("0.0.0.0:{}", Self::CONTAINER_PORT),
                "--no-store-on-disk".to_string(),
                "--consistency=1.0".to_string(),
            ],
        )
            .into();
        let image = image.with_network(network);
        let container = docker_client.cli.run(image);
        let ip_address = docker_client
            .get_network_ip_address(&container, network)
            .await?;
        let host_port = container.get_host_port_ipv4(Self::CONTAINER_PORT);

        let full_address = format!("http://{}:{}/", ip_address, Self::CONTAINER_PORT);
        let local_address = format!("http://127.0.0.1:{}/", host_port);
        tracing::info!("Datastore container is running at {}", full_address);
        Ok(Datastore {
            container,
            local_address,
            address: full_address,
        })
    }
}
