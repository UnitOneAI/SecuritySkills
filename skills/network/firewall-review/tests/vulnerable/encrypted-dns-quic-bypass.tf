resource "aws_security_group_rule" "allow_public_doh" {
  type              = "egress"
  security_group_id = aws_security_group.workload.id
  protocol          = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_blocks       = ["1.1.1.1/32", "8.8.8.8/32"]
  description       = "Temporary DoH exception without owner or expiry"
}

resource "aws_security_group_rule" "allow_dot" {
  type              = "egress"
  security_group_id = aws_security_group.workload.id
  protocol          = "tcp"
  from_port         = 853
  to_port           = 853
  cidr_blocks       = ["0.0.0.0/0"]
  description       = "Allow DNS over TLS"
}

resource "aws_security_group_rule" "allow_quic_direct" {
  type              = "egress"
  security_group_id = aws_security_group.workload.id
  protocol          = "udp"
  from_port         = 443
  to_port           = 443
  cidr_blocks       = ["0.0.0.0/0"]
  description       = "Allow direct HTTP/3 for troubleshooting"
}
