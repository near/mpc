use serde::Deserialize;

/// Partial JSON schema for `terraform show -json` output.
#[derive(Deserialize)]
pub(super) struct TerraformInfraShowOutput {
    pub values: RootValues,
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
            .get(0)
            .and_then(|ni| ni.access_config.get(0))
            .map(|ac| ac.nat_ip.clone())
    }
}

impl Resource {
    pub fn as_mpc_nomad_client(&self) -> Option<(usize, GoogleComputeInstance)> {
        let name_start = "google_compute_instance.nomad_client_mpc[";
        if self.type_ == "google_compute_instance" && self.address.starts_with(name_start) {
            let index: usize = self.address[name_start.len()..self.address.len() - 1]
                .parse()
                .unwrap();
            if let ResourceValues::GoogleComputeInstance(instance) = &self.values {
                Some((index, instance.clone()))
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
