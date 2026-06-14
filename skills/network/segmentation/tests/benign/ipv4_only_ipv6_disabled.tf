resource "aws_vpc" "app" {
  cidr_block                       = "10.20.0.0/16"
  assign_generated_ipv6_cidr_block = false
}

resource "aws_security_group" "app" {
  name   = "app-egress-restricted"
  vpc_id = aws_vpc.app.id

  egress {
    description = "HTTPS to approved proxy"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.20.30.40/32"]
  }
}
