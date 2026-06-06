resource "aws_security_group_rule" "allow_dot" {
  type              = "egress"
  security_group_id = aws_security_group.workload.id
  protocol          = "tcp"
  from_port         = 853
  to_port           = 853
  cidr_blocks       = ["0.0.0.0/0"]
  description       = "Temporary encrypted DNS exception"
}

resource "aws_security_group_rule" "allow_quic" {
  type              = "egress"
  security_group_id = aws_security_group.workload.id
  protocol          = "udp"
  from_port         = 443
  to_port           = 443
  cidr_blocks       = ["0.0.0.0/0"]
  description       = "Allow HTTP/3 directly"
}
