resource "aws_security_group" "db_public" {
  name        = "customer-db-public"
  description = "Public database access for a production RDS instance"
  vpc_id      = aws_vpc.main.id
}

resource "aws_security_group_rule" "postgres_anywhere" {
  type              = "ingress"
  security_group_id = aws_security_group.db_public.id
  protocol          = "tcp"
  from_port         = 5432
  to_port           = 5432
  cidr_blocks       = ["0.0.0.0/0"]
}

resource "aws_db_instance" "customer" {
  identifier                      = "customer-prod"
  engine                          = "postgres"
  instance_class                  = "db.m7g.large"
  allocated_storage               = 100
  publicly_accessible             = true
  vpc_security_group_ids          = [aws_security_group.db_public.id]
  storage_encrypted               = false
  backup_retention_period         = 1
  deletion_protection             = false
  skip_final_snapshot             = true
  enabled_cloudwatch_logs_exports = []
  performance_insights_enabled    = false
}

resource "aws_rds_cluster" "payments" {
  cluster_identifier      = "payments-prod"
  engine                  = "aurora-mysql"
  storage_encrypted       = false
  backup_retention_period = 1
  deletion_protection     = false
  skip_final_snapshot     = true
}
