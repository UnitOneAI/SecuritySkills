resource "aws_vpc" "prod" {
  cidr_block = "10.20.0.0/16"
}

resource "aws_security_group" "app" {
  name   = "app"
  vpc_id = aws_vpc.prod.id
}

resource "aws_security_group" "db" {
  name   = "db"
  vpc_id = aws_vpc.prod.id

  ingress {
    description     = "Only app workloads can reach Postgres"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.app.id]
  }

  egress {
    description = "No broad outbound path from database workloads"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = []
  }
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.prod.id

  # The implicit VPC-local route is reachability substrate. Segmentation review
  # should combine this with workload-attached SG/NACL evidence before scoring.
  route {
    cidr_block = aws_vpc.prod.cidr_block
    gateway_id = "local"
  }
}
