resource "google_cloud_run_v2_service" "admin_api" {
  name     = "admin-api"
  location = "us-central1"
  ingress  = "INGRESS_TRAFFIC_ALL"

  template {
    containers {
      image = "us-docker.pkg.dev/example/prod/admin-api:latest"
    }
  }
}

resource "google_cloud_run_v2_service_iam_member" "admin_public_invoker" {
  project  = google_cloud_run_v2_service.admin_api.project
  location = google_cloud_run_v2_service.admin_api.location
  name     = google_cloud_run_v2_service.admin_api.name
  role     = "roles/run.invoker"
  member   = "allUsers"
}
