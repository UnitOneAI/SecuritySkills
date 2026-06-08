resource "google_container_cluster" "admin" {
  name     = "admin-prod"
  location = "us-central1"

  private_cluster_config {
    enable_private_nodes    = false
    enable_private_endpoint = false
  }

  master_authorized_networks_config {
    cidr_blocks {
      cidr_block   = "0.0.0.0/0"
      display_name = "anywhere"
    }
  }

  network_policy {
    enabled = false
  }

  binary_authorization {
    evaluation_mode = "DISABLED"
  }

  enable_shielded_nodes = false
}

resource "google_container_node_pool" "default" {
  name     = "default-pool"
  cluster  = google_container_cluster.admin.name
  location = "us-central1"

  node_config {
    service_account = "default"
    oauth_scopes    = ["https://www.googleapis.com/auth/cloud-platform"]

    workload_metadata_config {
      mode = "GCE_METADATA"
    }
  }
}
