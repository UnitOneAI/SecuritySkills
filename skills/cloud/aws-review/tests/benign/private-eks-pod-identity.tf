resource "aws_eks_cluster" "payments" {
  name     = "payments-prod"
  role_arn = aws_iam_role.eks_control_plane.arn

  vpc_config {
    subnet_ids              = aws_subnet.private[*].id
    endpoint_private_access = true
    endpoint_public_access  = false
    public_access_cidrs     = []
  }

  access_config {
    authentication_mode                         = "API_AND_CONFIG_MAP"
    bootstrap_cluster_creator_admin_permissions = false
  }

  encryption_config {
    provider {
      key_arn = aws_kms_key.eks_secrets.arn
    }
    resources = ["secrets"]
  }

  enabled_cluster_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]
}

resource "aws_eks_node_group" "payments" {
  cluster_name    = aws_eks_cluster.payments.name
  node_group_name = "payments-private"
  node_role_arn   = aws_iam_role.eks_nodes_minimal.arn
  subnet_ids      = aws_subnet.private[*].id

  launch_template {
    id      = aws_launch_template.eks_nodes.id
    version = "$Latest"
  }
}

resource "aws_eks_pod_identity_association" "payments_api" {
  cluster_name    = aws_eks_cluster.payments.name
  namespace       = "payments"
  service_account = "api"
  role_arn        = aws_iam_role.payments_pod.arn
}
