use colored::Colorize;
use serde::Deserialize;

use super::State;

/// Partial JSON schema for `terraform show -json` output.
#[derive(Deserialize)]
pub(super) struct TerraformInfraShowOutput {
    pub values: RootValues,
}
//
//        let output: TerraformInfraShowOutput =
//            serde_json::from_slice(&output.stdout).expect("Failed to parse terraform show output");
//
//        for resource in &output.values.root_module.resources {
//            if let Some(instance) = resource.as_mpc_nomad_server() {
//                println!(
//                    "Nomad server: http://{}",
//                    instance.nat_ip().unwrap_or_default()
//                );
//            }
//        }
//        for resource in &output.values.root_module.resources {
//            if let Some((index, instance)) = resource.as_mpc_nomad_client() {
//                println!(
//                    "Nomad client #{}: zone {}, instance type {}, debug: http://{}:8080/debug/tasks",
//                    index,
//                    instance.zone,
//                    instance.machine_type,
//                    instance.nat_ip().unwrap_or_default()
//                );
//            }
//        }

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
        let debug_url = format!(
            "http://{}:8080/debug/",
            self.instance.nat_ip().unwrap_or_default()
        );
        let tasks = format!("{}tasks", debug_url);
        let tasks = match reqwest::get(&tasks).await {
            Ok(val) => val
                .text()
                .await
                .unwrap_or("error unwrapping tasks".to_string())
                .to_string(),
            Err(e) => e.to_string(),
        };
        State::new(&tasks).unwrap()
    }
    pub async fn desc(&self) {
        let debug_url = format!(
            "http://{}:8080/debug/",
            self.instance.nat_ip().unwrap_or_default()
        );
        let tasks = format!("{}tasks", debug_url);
        let tasks = match reqwest::get(&tasks).await {
            Ok(val) => val
                .text()
                .await
                .unwrap_or("error unwrapping tasks".to_string())
                .to_string(),
            Err(e) => e.to_string(),
        };
        let state = State::new(&tasks).unwrap();
        let signatures = format!("{}signatures", debug_url);
        let signatures = match reqwest::get(&signatures).await {
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

    //pub async fn describe_nomad_client(&self) {
    //    if let Some((index, instance)) = self.as_mpc_nomad_client() {
    //        let debug_url = format!(
    //            "http://{}:8080/debug/",
    //            instance.nat_ip().unwrap_or_default()
    //        );
    //        let tasks = format!("{}tasks", debug_url);
    //        let tasks = match reqwest::get(&tasks).await {
    //            Ok(val) => val
    //                .text()
    //                .await
    //                .unwrap_or("error unwrapping text".to_string())
    //                .to_string(),
    //            Err(e) => e.to_string(),
    //        };
    //        println!(
    //            "Nomad client #{}: zone {}, instance type {}, debug: http://{}:8080/debug/tasks",
    //            index,
    //            instance.zone,
    //            instance.machine_type,
    //            instance.nat_ip().unwrap_or_default()
    //        );
    //        println!("tasks: {}", tasks);
    //    }
    //}
}
