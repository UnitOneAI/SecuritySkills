resource "aws_kms_key" "rds" {
  description         = "Customer managed key for production RDS and Aurora data"
  enable_key_rotation = true
}

resource "aws_security_group" "rds_private" {
  name        = "orders-rds-private"
  description = "Private application subnet access to Aurora"
  vpc_id      = aws_vpc.main.id
}

resource "aws_security_group_rule" "postgres_from_app" {
  type                     = "ingress"
  security_group_id        = aws_security_group.rds_private.id
  protocol                 = "tcp"
  from_port                = 5432
  to_port                  = 5432
  source_security_group_id = aws_security_group.app.id
}

resource "aws_db_subnet_group" "private" {
  name       = "orders-private"
  subnet_ids = [aws_subnet.private_a.id, aws_subnet.private_b.id]
}

resource "aws_rds_cluster" "orders" {
  cluster_identifier              = "orders-prod"
  engine                          = "aurora-postgresql"
  storage_encrypted               = true
  kms_key_id                      = aws_kms_key.rds.arn
  backup_retention_period         = 14
  deletion_protection             = true
  db_subnet_group_name            = aws_db_subnet_group.private.name
  vpc_security_group_ids          = [aws_security_group.rds_private.id]
  enabled_cloudwatch_logs_exports = ["postgresql"]
}

resource "aws_rds_cluster_instance" "orders" {
  cluster_identifier              = aws_rds_cluster.orders.id
  instance_class                  = "db.r7g.large"
  engine                          = aws_rds_cluster.orders.engine
  publicly_accessible             = false
  performance_insights_enabled    = true
  performance_insights_kms_key_id = aws_kms_key.rds.arn
}
