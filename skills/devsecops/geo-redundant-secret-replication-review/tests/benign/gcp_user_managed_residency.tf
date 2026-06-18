resource "google_secret_manager_secret" "tenant_token" {
  secret_id = "tenant-a-token"

  replication {
    user_managed {
      replicas {
        location = "us-east1"
      }
      replicas {
        location = "us-west1"
      }
    }
  }
}

resource "google_secret_manager_secret_iam_binding" "workload_readers" {
  secret_id = google_secret_manager_secret.tenant_token.id
  role      = "roles/secretmanager.secretAccessor"
  members   = ["serviceAccount:tenant-a-worker@example.iam.gserviceaccount.com"]
}
