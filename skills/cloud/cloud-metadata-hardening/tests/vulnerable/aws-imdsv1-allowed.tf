resource "aws_instance" "web" {
  ami           = "ami-1234567890abcdef0"
  instance_type = "t3.micro"
  iam_instance_profile = aws_iam_instance_profile.web.name

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "optional"
    http_put_response_hop_limit = 2
  }
}

resource "aws_launch_template" "workers" {
  name_prefix   = "worker-"
  image_id      = "ami-1234567890abcdef0"
  instance_type = "t3.small"

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "optional"
  }
}

resource "aws_iam_role_policy" "broad_node_permissions" {
  name = "broad-node-permissions"
  role = aws_iam_role.web.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}
