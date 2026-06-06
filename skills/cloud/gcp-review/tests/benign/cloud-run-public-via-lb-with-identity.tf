resource "google_service_account" "public_api" {
  account_id   = "public-api"
  display_name = "Public API runtime identity"
}

resource "google_cloud_run_v2_service" "public_api" {
  name     = "public-api"
  location = "us-central1"
  ingress  = "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER"

  template {
    service_account = google_service_account.public_api.email

    containers {
      image = "us-docker.pkg.dev/example/prod/public-api@sha256:def456"
    }

    vpc_access {
      egress = "PRIVATE_RANGES_ONLY"
    }
  }
}

resource "google_cloud_run_v2_service_iam_member" "public_invoker" {
  project  = google_cloud_run_v2_service.public_api.project
  location = google_cloud_run_v2_service.public_api.location
  name     = google_cloud_run_v2_service.public_api.name
  role     = "roles/run.invoker"
  member   = "allUsers"
}
