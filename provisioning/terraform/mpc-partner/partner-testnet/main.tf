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

  container = {
    image = var.image
    args  = ["start"]
    port  = "3000"

    env = concat(var.static_env, [
      {
        name  = "MPC_NODE_ID"
        value = "${count.index}"
      },
      {
        name  = "MPC_ACCOUNT_ID"
        value = var.node_configs["${count.index}"].account
      },
      {
        name  = "MPC_CIPHER_PK"
        value = var.node_configs["${count.index}"].cipher_pk
      },
      {
        name  = "MPC_ACCOUNT_SK"
        value = data.google_secret_manager_secret_version.account_sk_secret_id[count.index].secret_data
      },
      {
        name  = "MPC_CIPHER_SK"
        value = data.google_secret_manager_secret_version.cipher_sk_secret_id[count.index].secret_data
      },
      {
        name  = "MPC_SIGN_SK"
        value = data.google_secret_manager_secret_version.sign_sk_secret_id[count.index] != null ? data.google_secret_manager_secret_version.sign_sk_secret_id[count.index].secret_data : data.google_secret_manager_secret_version.account_sk_secret_id[count.index].secret_data
      },
      {
        name  = "AWS_ACCESS_KEY_ID"
        value = data.google_secret_manager_secret_version.aws_access_key_secret_id.secret_data
      },
      {
        name  = "AWS_SECRET_ACCESS_KEY"
        value = data.google_secret_manager_secret_version.aws_secret_key_secret_id.secret_data
      },
      {
        name  = "MPC_LOCAL_ADDRESS"
        value = "http://${google_compute_global_address.external_ips[count.index].address}"
      },
      {
        name  = "MPC_SK_SHARE_SECRET_ID"
        value = var.node_configs["${count.index}"].sk_share_secret_id
      },
      {
        name  = "MPC_ENV",
        value = var.env
      },
      {
        name  = "GCP_KEYSHARE_SECRET_ID"
        value = var.node_configs["${count.index}"].gcp_keyshare_secret_id
      },
      {
        name  = "GCP_LOCAL_ENCRYPTION_KEY_SECRET_ID"
        value = var.node_configs["${count.index}"].gcp_local_encryption_key_secret_id
      },
      {
        name  = "GCP_P2P_PRIVATE_KEY_SECRET_ID"
        value = var.node_configs["${count.index}"].gcp_p2p_private_key_secret_id
      },
      {
        name  = "GCP_ACCOUNT_SK_SECRET_ID"
        value = var.node_configs["${count.index}"].gcp_account_sk_secret_id
      },
    ])
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
resource "google_compute_global_address" "external_ips" {
  count        = length(var.node_configs)
  name         = "multichain-dev-parnter-${count.index}"
  address_type = "EXTERNAL"
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

  startup_script = "docker rm watchtower ; docker run -d --name watchtower -v /var/run/docker.sock:/var/run/docker.sock containrrr/watchtower --debug --interval 30"

  source_image = reverse(split("/", module.gce-container[count.index].source_image))[0]
  metadata     = merge(var.additional_metadata, { "gce-container-declaration" = module.gce-container["${count.index}"].metadata_value })
  tags = [
    "multichain",
    "allow-ssh"
  ]
  labels = {
    "container-vm" = module.gce-container[count.index].vm_container_label
  }

  depends_on = [google_compute_global_address.external_ips]
}


module "instances" {
  count      = var.scenario == "old" ? length(var.node_configs) : 0
  source     = "../modules/instance-from-tpl"
  region     = var.region
  project_id = var.project_id
  hostname   = "multichain-testnet-partner-${count.index}"
  network    = var.network
  subnetwork = var.subnetwork

  instance_template = module.ig_template[count.index].self_link_unique

}

#####################################################################
# Firewall and loadbalancer template
#####################################################################
# Old rule delete Once new is ok
resource "google_compute_health_check" "multichain_healthcheck" {
  count = var.scenario == "old" ? 1 : 0
  name  = "multichain-testnet-partner-healthcheck"

  http_health_check {
    port         = 3000
    request_path = "/"
  }

}

# Old forwarding rule is done per node config
# resource "google_compute_global_forwarding_rule" "default" {
#   count                 = var.scenario == "old" ? length(var.node_configs) : 0
#   name                  = "multichain-partner-rule-${count.index}"
#   target                = google_compute_target_http_proxy.default[count.index].id
#   port_range            = "80"
#   load_balancing_scheme = "EXTERNAL"
#   ip_address            = google_compute_global_address.external_ips[count.index].address
# }

# Old http proxy
# resource "google_compute_target_http_proxy" "default" {
#   count       = var.scenario == "old" ? length(var.node_configs) : 0
#   name        = "multichain-partner-target-proxy-${count.index}"
#   description = "a description"
#   url_map     = google_compute_url_map.default[count.index].id
# }

# Old URL maps
# resource "google_compute_url_map" "default" {
#   count           = var.scenario == "old" ? length(var.node_configs) : 0
#   name            = "multichain-partner-url-map-${count.index}"
#   default_service = google_compute_backend_service.multichain_backend.id
# }

# Old Backend service
# resource "google_compute_backend_service" "multichain_backend" {
#   name                  = "multichain-partner-backend-service"
#   load_balancing_scheme = "EXTERNAL"

#   backend {
#     group = google_compute_instance_group.multichain_group.id
#   }

#   health_checks = [google_compute_health_check.multichain_healthcheck.id]
# }

# Old instance group
resource "google_compute_instance_group" "multichain_group" {
  name      = "multichain-partner-instance-group"
  instances = module.instances[*].self_links[0]

  zone = var.zone
  named_port {
    name = "http"
    port = 3000
  }
}

# Old firewall
resource "google_compute_firewall" "app_port" {
  count   = var.scenario == "old" ? 1 : 0
  name    = "allow-multichain-healthcheck-access"
  network = var.network

  source_ranges = ["130.211.0.0/22", "35.191.0.0/16"]
  source_tags   = ["multichain"]

  allow {
    protocol = "tcp"
    ports    = ["80", "3000"]
  }

}

#####################################################################
# New LOAD BALANCER definition
#####################################################################

resource "google_compute_health_check" "multichain_tcp_healthcheck" {
  name = "multichain-testnet-partner-tcp-healthcheck"

  tcp_health_check {
    port = "80"
  }
}

resource "google_compute_backend_service" "multichain_backend" {
  name                  = "multichain-partner-backend-service"
  load_balancing_scheme = "EXTERNAL"
  protocol              = "TCP"
  port_name             = "http"
  timeout_sec           = 30
  backend {
    group = google_compute_instance_group.multichain_group.id
  }

  health_checks = [google_compute_health_check.multichain_tcp_healthcheck.id]
}

# resource "google_compute_url_map" "default" {
#   count           = length(var.node_configs)
#   name            = "multichain-partner-url-map-${count.index}"
#   default_service = google_compute_backend_service.multichain_backend.id
# }

# resource "google_compute_target_http_proxy" "default" {
#   count       = length(var.node_configs)
#   name        = "multichain-partner-target-proxy-${count.index}"
#   description = "a description"
#   url_map     = google_compute_url_map.default[count.index].id
# }

# resource "google_compute_target_tcp_proxy" "default" {
#   count           = length(var.node_configs)
#   backend_service = "https://www.googleapis.com/compute/v1/projects/nearone-multichain/global/backendServices/testnet-lb"
#   name            = "multichain-partner-target-tcp-proxy-${count.index}"
#   project         = "nearone-multichain"
#   proxy_header    = "NONE"
# }

resource "google_compute_target_tcp_proxy" "default" {
  count           = length(var.node_configs)
  name            = "multichain-partner-target-proxy-${count.index}"
  description     = "a description"
  backend_service = google_compute_backend_service.multichain_backend.id
}

resource "google_compute_global_forwarding_rule" "default" {
  count                 = length(var.node_configs)
  name                  = "multichain-partner-rule-${count.index}"
  ip_protocol           = "TCP"
  load_balancing_scheme = "EXTERNAL"
  port_range            = "80"
  target                = google_compute_target_tcp_proxy.default[count.index].id
  ip_address            = google_compute_global_address.external_ips[count.index].address
}

# Current config
# resource "google_compute_global_forwarding_rule" "fe" {
#   ip_protocol           = "TCP"
#   name                  = "fe"
#   load_balancing_scheme = "EXTERNAL_MANAGED"
#   port_range            = "80-80"
#   project               = "nearone-multichain"
#   target                = "https://www.googleapis.com/compute/beta/projects/nearone-multichain/global/targetTcpProxies/testnet-lb-target-proxy"
#   ip_address            = "34.107.154.206"
# }


# resource "google_compute_target_tcp_proxy" "testnet_lb_target_proxy" {
#   backend_service = "https://www.googleapis.com/compute/v1/projects/nearone-multichain/global/backendServices/testnet-lb"
#   name            = "testnet-lb-target-proxy"
#   project         = "nearone-multichain"
#   proxy_header    = "NONE"
# }
# terraform import google_compute_target_tcp_proxy.testnet_lb_target_proxy projects/nearone-multichain/global/targetTcpProxies/testnet-lb-target-proxy
