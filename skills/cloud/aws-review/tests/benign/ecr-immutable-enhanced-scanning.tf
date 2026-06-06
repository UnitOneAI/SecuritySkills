resource "aws_ecr_repository" "app" {
  name                 = "prod/app"
  image_tag_mutability = "IMMUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }
}

resource "aws_ecr_registry_scanning_configuration" "registry" {
  scan_type = "ENHANCED"

  rule {
    scan_frequency = "CONTINUOUS_SCAN"

    repository_filter {
      filter      = "prod/*"
      filter_type = "WILDCARD"
    }
  }
}

locals {
  release_image_digest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
}
