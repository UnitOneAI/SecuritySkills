resource "aws_security_group" "api" {
  name = "api-segmentation"

  egress {
    description = "IPv4 egress is restricted to internal networks"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["10.0.0.0/8"]
  }

  egress {
    description      = "IPv6 egress unintentionally bypasses the IPv4 zone policy"
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    ipv6_cidr_blocks = ["::/0"]
  }
}
