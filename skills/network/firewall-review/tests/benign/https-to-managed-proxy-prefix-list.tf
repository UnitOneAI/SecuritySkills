resource "aws_ec2_managed_prefix_list" "corp_egress_proxy" {
  name           = "corp-egress-proxy-endpoints"
  address_family = "IPv4"
  max_entries    = 2

  entry {
    cidr        = "10.42.16.10/32"
    description = "Blue egress proxy"
  }

  entry {
    cidr        = "10.42.16.11/32"
    description = "Green egress proxy"
  }
}

resource "aws_security_group_rule" "https_only_to_proxy" {
  type              = "egress"
  security_group_id = aws_security_group.workload.id
  protocol          = "tcp"
  from_port         = 443
  to_port           = 443
  prefix_list_ids   = [aws_ec2_managed_prefix_list.corp_egress_proxy.id]
  description       = "HTTPS only to inspected corporate egress proxy fleet"
}
