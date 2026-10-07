resource "aws_security_group_rule" "open" {
  cidr_blocks = ["0.0.0.0/0"]
}
