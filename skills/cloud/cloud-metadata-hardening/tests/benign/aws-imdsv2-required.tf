resource "aws_instance" "worker" {
  ami           = "ami-1234567890abcdef0"
  instance_type = "t3.micro"
  iam_instance_profile = aws_iam_instance_profile.worker.name

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }
}

resource "aws_launch_template" "container_worker" {
  name_prefix   = "container-worker-"
  image_id      = "ami-1234567890abcdef0"
  instance_type = "t3.small"

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 2
  }
}

resource "aws_iam_role_policy" "narrow_worker_permissions" {
  name = "narrow-worker-permissions"
  role = aws_iam_role.worker.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "sqs:ReceiveMessage",
        "sqs:DeleteMessage"
      ]
      Resource = aws_sqs_queue.jobs.arn
    }]
  })
}
