resource "google_container_cluster" "payments" {
  name     = "payments-prod"
  location = "us-central1"

  remove_default_node_pool = true
  initial_node_count       = 1

  private_cluster_config {
    enable_private_nodes    = true
    enable_private_endpoint = true
    master_ipv4_cidr_block  = "172.16.0.0/28"
  }

  master_authorized_networks_config {
    cidr_blocks {
      cidr_block   = "203.0.113.0/24"
      display_name = "corp-vpn"
    }
  }

  workload_identity_config {
    workload_pool = "example-prod.svc.id.goog"
  }

  network_policy {
    enabled  = true
    provider = "CALICO"
  }

  binary_authorization {
    evaluation_mode = "PROJECT_SINGLETON_POLICY_ENFORCE"
  }

  enable_shielded_nodes = true
}

resource "google_container_node_pool" "payments" {
  name     = "payments-private"
  cluster  = google_container_cluster.payments.name
  location = "us-central1"

  node_config {
    service_account = "gke-nodes@example-prod.iam.gserviceaccount.com"
    oauth_scopes    = ["https://www.googleapis.com/auth/logging.write", "https://www.googleapis.com/auth/monitoring"]

    workload_metadata_config {
      mode = "GKE_METADATA"
    }
  }
}
