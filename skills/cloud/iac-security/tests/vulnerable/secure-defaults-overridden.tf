variable "allowed_cidrs" {
  type    = list(string)
  default = ["10.0.0.0/8"]
}

variable "db_public" {
  type    = bool
  default = false
}

resource "aws_security_group_rule" "admin" {
  type        = "ingress"
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = var.allowed_cidrs
}

resource "aws_db_instance" "payments" {
  publicly_accessible = var.db_public
}
