provider "google" {
  project = var.project_id
}
provider "google-beta" {
  project = var.project_id
}

resource "google_compute_project_metadata_item" "project_logging" {
  key   = "google-logging-enabled"
  value = "true"
}

module "gce-container" {
  count   = length(var.node_configs)
  source  = "terraform-google-modules/container-vm/google"
  version = "~> 3.0"
}

#####################################################################
# Cloud init config
#####################################################################
data "cloudinit_config" "mpc_config" {
  count         = length(var.node_configs)
  gzip          = false
  base64_encode = false

  part {
    content_type = "text/cloud-config"
    content = templatefile("../configs/mpc_cloud_config.yml", {
      docker_image                       = var.image
      data_dir                           = "/home/mpc/"
      gcp_project_id                     = var.project_id
      gcp_keyshare_secret_id             = var.node_configs["${count.index}"].gcp_keyshare_secret_id
      gcp_local_encryption_key_secret_id = var.node_configs["${count.index}"].gcp_local_encryption_key_secret_id
      gcp_p2p_private_key_secret_id      = var.node_configs["${count.index}"].gcp_p2p_private_key_secret_id
      gcp_account_sk_secret_id           = var.node_configs["${count.index}"].gcp_account_sk_secret_id
      mpc_account_id                     = var.node_configs["${count.index}"].account
      near_boot_nodes                    = var.near_boot_nodes
      mpc_contract_id                    = "v1.signer-prod.testnet"
      mpc_local_address                  = var.node_configs[count.index].domain
      chain_id                           = var.env
    })
    filename = "mpc_cloud_config.yml"
  }
}


#####################################################################
# Account definitions
#####################################################################

resource "google_service_account" "service_account" {
  account_id   = "multichain-${var.env}"
  display_name = "Multichain ${var.env} Account"
}

resource "google_project_iam_member" "sa-roles" {
  for_each = toset([
    "roles/datastore.user",
    "roles/secretmanager.admin",
    "roles/storage.objectAdmin",
    "roles/iam.serviceAccountAdmin",
    "roles/logging.logWriter",
  ])

  role    = each.key
  member  = "serviceAccount:${google_service_account.service_account.email}"
  project = var.project_id
}


#####################################################################
# External ip resevation
#####################################################################
resource "google_compute_address" "external_ips" {
  count        = length(var.node_configs)
  name         = "multichain-dev-partner-${count.index}"
  region       = var.region
  address_type = "EXTERNAL"
  lifecycle {
    prevent_destroy = true
  }
}

#####################################################################
# Instance definitions
#####################################################################
module "ig_template" {
  count      = length(var.node_configs)
  source     = "../modules/mig_template"
  network    = var.network
  subnetwork = var.subnetwork
  region     = var.region
  service_account = {
    email  = google_service_account.service_account.email,
    scopes = ["cloud-platform"]
  }
  name_prefix          = "multichain-partner-${count.index}"
  source_image_family  = "cos-stable"
  source_image_project = "cos-cloud"
  machine_type         = "n2d-standard-16"

  startup_script = file("${path.module}/../scripts/mpc-init.sh")

  additional_disks = [{
    description  = "Main data disk"
    disk_name    = "mpc-partner-testnet-${count.index}"
    auto_delete  = false
    boot         = false
    disk_size_gb = 500
    disk_type    = "pd-ssd"
    disk_labels  = {}
    device_name  = "mpc-partner-testnet-${count.index}"
  }]

  source_image = reverse(split("/", module.gce-container[count.index].source_image))[0]
  metadata     = { user-data = data.cloudinit_config.mpc_config[count.index].rendered }

  tags = [
    "multichain",
    "allow-ssh"
  ]
  labels = {
    "container-vm" = module.gce-container[count.index].vm_container_label
  }

  depends_on = [google_compute_address.external_ips]
}

module "instances" {
  count      = length(var.node_configs)
  source     = "../modules/instance-from-tpl"
  region     = var.region
  project_id = var.project_id
  hostname   = "multichain-testnet-partner-${count.index}"
  network    = var.network
  subnetwork = var.subnetwork
  access_config = [
    [
      {
        nat_ip       = google_compute_address.external_ips[count.index].address
        network_tier = "PREMIUM"
      }
    ]
  ]
  instance_template = module.ig_template[count.index].self_link_unique
}

#####################################################################
# Firewall template
#####################################################################
resource "google_compute_firewall" "testnet-mpc" {
  name    = "testnet-mpc"
  network = "default"
  allow {
    protocol = "tcp"
    ports    = ["80", "3030", "8080", "24567"]
  }
  source_ranges = ["0.0.0.0/0"]
}
