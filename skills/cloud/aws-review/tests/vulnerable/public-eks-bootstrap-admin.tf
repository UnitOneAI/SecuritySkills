resource "aws_eks_cluster" "admin" {
  name     = "admin-prod"
  role_arn = aws_iam_role.eks_control_plane.arn

  vpc_config {
    subnet_ids              = aws_subnet.public[*].id
    endpoint_private_access = false
    endpoint_public_access  = true
    public_access_cidrs     = ["0.0.0.0/0"]
  }

  access_config {
    authentication_mode                         = "CONFIG_MAP"
    bootstrap_cluster_creator_admin_permissions = true
  }

  enabled_cluster_log_types = []
}

resource "aws_eks_node_group" "default" {
  cluster_name    = aws_eks_cluster.admin.name
  node_group_name = "default"
  node_role_arn   = aws_iam_role.broad_node.arn
  subnet_ids      = aws_subnet.public[*].id
}
