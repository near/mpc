use crate::terraform::State;
use colored::Colorize;
use futures::future::join_all;
use near_sdk::log;
use serde::Deserialize;

/// Partial JSON schema for `terraform show -json` output.
#[derive(Deserialize)]
pub struct TerraformInfraShowOutput {
    pub(super) values: RootValues,
}

impl TerraformInfraShowOutput {
    pub async fn state(&self) -> Vec<State> {
        let clients: Vec<_> = self
            .values
            .root_module
            .resources
            .iter()
            .filter_map(|resource| resource.as_mpc_nomad_client())
            .collect();
        let states = clients.iter().map(|instance| instance.get_state());
        join_all(states).await
    }

    pub async fn cluster_is_ready(&self) -> bool {
        let states = self.state().await;
        println!("states: {:?}", states);
        !states.is_empty()
            && states
                .into_iter()
                .all(|s| s != State::Unavailable && s != State::WaitingForSync)
    }
}

#[derive(Deserialize)]
pub(super) struct RootValues {
    pub root_module: RootModule,
}

#[derive(Deserialize)]
pub(super) struct RootModule {
    pub resources: Vec<Resource>,
}

#[derive(Deserialize)]
pub(super) struct Resource {
    pub address: String,
    #[serde(rename = "type")]
    pub type_: String,
    pub values: ResourceValues,
}

#[derive(Deserialize)]
#[serde(untagged)]
pub(super) enum ResourceValues {
    GoogleComputeInstance(GoogleComputeInstance),
    Other(Other),
}

#[derive(Deserialize, Clone)]
pub(super) struct GoogleComputeInstance {
    pub machine_type: String,
    pub network_interface: Vec<NetworkInterface>,
    pub zone: String,
}

#[derive(Deserialize, Clone)]
pub(super) struct NetworkInterface {
    pub access_config: Vec<AccessConfig>,
}

#[derive(Deserialize, Clone)]
pub(super) struct AccessConfig {
    pub nat_ip: String,
}

#[derive(Deserialize, Clone)]
pub(super) struct Other {}

impl GoogleComputeInstance {
    pub fn nat_ip(&self) -> Option<String> {
        self.network_interface
            .first()
            .and_then(|ni| ni.access_config.first())
            .map(|ac| ac.nat_ip.clone())
    }
}

pub struct MpcNomadClient {
    pub index: usize,
    pub instance: GoogleComputeInstance,
}

impl MpcNomadClient {
    pub async fn get_state(&self) -> State {
        match reqwest::get(self.tasks_url()).await {
            Ok(val) => State::new(
                &val.text()
                    .await
                    .unwrap_or("error unwrapping tasks".to_string())
                    .to_string(),
            )
            .unwrap(),
            Err(e) => {
                log!("could not get request: {}", e);
                State::Unavailable
            }
        }
    }
    pub fn debug_url(&self) -> String {
        format!(
            "http://{}:8080/debug/",
            self.instance.nat_ip().unwrap_or_default()
        )
    }
    pub fn tasks_url(&self) -> String {
        format!("{}tasks", self.debug_url())
    }
    pub fn signatures_url(&self) -> String {
        format!("{}signatures", self.debug_url())
    }
    pub async fn desc(&self) {
        //let debug_url = self.debug_url();
        //let tasks = format!("{}tasks", debug_url);
        let tasks = match reqwest::get(self.tasks_url()).await {
            Ok(val) => val
                .text()
                .await
                .unwrap_or("error unwrapping tasks".to_string())
                .to_string(),
            Err(e) => e.to_string(),
        };
        let state = State::new(&tasks).unwrap();
        let signatures = match reqwest::get(&self.signatures_url()).await {
            Ok(val) => val
                .text()
                .await
                .unwrap_or("error unwrapping signatures".to_string())
                .to_string(),
            Err(e) => e.to_string(),
        };
        println!(
            "Nomad client #{}: zone {}, instance type {}, debug: http://{}:8080/debug/tasks",
            self.index,
            self.instance.zone,
            self.instance.machine_type,
            self.instance.nat_ip().unwrap_or_default()
        );
        println!(
            "{}\n{}",
            state.to_string().bold().bright_blue(),
            tasks.bright_blue()
        );
        println!(
            "{}\n{}",
            "signatures:".bold().bright_black(),
            signatures.bright_black()
        );
    }
}
impl Resource {
    pub fn as_mpc_nomad_client(&self) -> Option<MpcNomadClient> {
        let name_start = "google_compute_instance.nomad_client_mpc[";
        if self.type_ == "google_compute_instance" && self.address.starts_with(name_start) {
            let index: usize = self.address[name_start.len()..self.address.len() - 1]
                .parse()
                .unwrap();
            if let ResourceValues::GoogleComputeInstance(instance) = &self.values {
                Some(MpcNomadClient {
                    index,
                    instance: instance.clone(),
                })
            } else {
                None
            }
        } else {
            None
        }
    }

    pub fn as_mpc_nomad_server(&self) -> Option<GoogleComputeInstance> {
        let name = "google_compute_instance.nomad_server";
        if self.type_ == "google_compute_instance" && self.address == name {
            if let ResourceValues::GoogleComputeInstance(instance) = &self.values {
                Some(instance.clone())
            } else {
                None
            }
        } else {
            None
        }
    }
}
