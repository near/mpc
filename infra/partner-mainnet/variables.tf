variable "project_id" {
  description = "The project ID to deploy resource into"
  type        = string
}

variable "subnetwork" {
  description = "The name of the subnetwork to deploy instances into"
  type        = string
}

variable "mig_name" {
  description = "The desired name to assign to the deployed managed instance group"
  type        = string
  default     = "mpc-mig"
}

variable "image" {
  description = "The Docker image to deploy to GCE instances. Note: This is a public image repository used for updating your nodes, please do not change this"
  type        = string
}

variable "region" {
  description = "The GCP region to deploy instances into"
  type        = string
}

variable "zone" {
  type = string
}

variable "network" {
  description = "The GCP network"
  type        = string
}

variable "additional_metadata" {
  type        = map(any)
  description = "Additional metadata to attach to the instance"
  default = {
    cos-update-strategy : "update_enabled"
  }
}

variable "service_account" {
  type = object({
    email  = string,
    scopes = list(string)
  })
  default = {
    email  = ""
    scopes = ["cloud-platform"]
  }
}

variable "node_configs" {
  type = list(object({
    account                            = string
    domain                             = string
    gcp_local_encryption_key_secret_id = string
    gcp_keyshare_secret_id             = string
    gcp_p2p_private_key_secret_id      = string
    gcp_account_sk_secret_id           = string
  }))
}

variable "env" {
  type    = string
}

variable "near_boot_nodes" {
  type = string
}

variable "create_network" {
  default     = false
  description = "Do you want to create a new VPC network (true) or use default GCP network (false)?"
}

variable "domain" {
  description = "DNS name for your node"
}
