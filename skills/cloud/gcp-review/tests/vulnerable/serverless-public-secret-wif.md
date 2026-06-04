# Vulnerable Case: Public Serverless API With Literal Secret and Weak WIF

## Scenario

A GCP posture review includes Cloud Run, Cloud Functions v2, and Workload Identity Federation resources. No VM has a public IP and no firewall rule exposes SSH/RDP, but a serverless admin API is public and uses weak identity and secret controls.

## Evidence

```hcl
resource "google_cloud_run_v2_service" "admin_api" {
  name     = "admin-api"
  location = "us-central1"
  ingress  = "INGRESS_TRAFFIC_ALL"

  template {
    service_account = "123456789-compute@developer.gserviceaccount.com"

    containers {
      image = "us-docker.pkg.dev/example/admin/api:latest"

      env {
        name  = "ADMIN_API_TOKEN"
        value = "plain-text-token"
      }
    }
  }
}

resource "google_cloud_run_service_iam_member" "public_invoker" {
  service  = google_cloud_run_v2_service.admin_api.name
  location = google_cloud_run_v2_service.admin_api.location
  role     = "roles/run.invoker"
  member   = "allUsers"
}

resource "google_cloudfunctions2_function" "webhook" {
  name     = "webhook-handler"
  location = "us-central1"

  service_config {
    environment_variables = {
      STRIPE_WEBHOOK_SECRET = "whsec_plaintext_value"
    }
  }
}

resource "google_iam_workload_identity_pool_provider" "github" {
  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }

  attribute_mapping = {
    "google.subject"       = "assertion.sub"
    "attribute.repository" = "assertion.repository"
  }
}
```

## Expected Skill Result

Classify serverless findings as **Critical** or **High** depending on data sensitivity:

- Cloud Run admin API is internet-reachable and unauthenticated via `allUsers`.
- Runtime uses the default Compute Engine service account.
- Cloud Run and Functions v2 contain literal secret values.
- WIF provider lacks an `attribute_condition`, so the external identity provider is over-trusted.
- The absence of VM public IPs or broad firewall rules is not sufficient evidence of serverless safety.
