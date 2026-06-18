resource "google_secret_manager_secret" "tenant_token" {
  secret_id = "tenant-a-token"

  replication {
    automatic = true
  }
}

resource "google_secret_manager_secret_iam_binding" "support_readers" {
  secret_id = google_secret_manager_secret.tenant_token.id
  role      = "roles/secretmanager.secretAccessor"
  members   = ["group:support@example.com"]
}
