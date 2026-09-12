# ==============================================================================
# VPC & Network Architecture for SOC Platform Infrastructure
# ==============================================================================

resource "aws_vpc" "soc_vpc" {
  cidr_block           = "10.100.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "soc-vpc-enterprise"
  }
}

resource "aws_subnet" "soc_private_1" {
  vpc_id            = aws_vpc.soc_vpc.id
  cidr_block        = "10.100.1.0/24"
  availability_zone = "${var.aws_region}a"

  tags = {
    Name = "soc-subnet-private-1a"
  }
}

resource "aws_subnet" "soc_private_2" {
  vpc_id            = aws_vpc.soc_vpc.id
  cidr_block        = "10.100.2.0/24"
  availability_zone = "${var.aws_region}b"

  tags = {
    Name = "soc-subnet-private-1b"
  }
}

# ------------------------------------------------------------------------------
# Secure Bastion Security Group (Compliant Baseline)
# ------------------------------------------------------------------------------
resource "aws_security_group" "soc_bastion_sg" {
  name        = "soc-bastion-sg"
  description = "Compliant bastion security group restricted to corporate VPN IP"
  vpc_id      = aws_vpc.soc_vpc.id

  ingress {
    description = "SSH access restricted to corporate secure gateway CIDR"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["203.0.113.50/32"]
  }

  egress {
    description = "Outbound HTTPS for telemetry updates"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# ------------------------------------------------------------------------------
# VULNERABLE SECURITY GROUP (Deliberate IaC Misconfiguration for CSPM Demo)
# Triggers: Checkov CKV_AWS_24 (Ensure no security groups allow ingress from 0.0.0.0:0 to port 22)
# Triggers: Checkov CKV_AWS_260 (Ensure no security groups allow ingress from 0.0.0.0:0 to all ports)
# ------------------------------------------------------------------------------
resource "aws_security_group" "soc_insecure_demo_sg" {
  name        = "soc-insecure-open-ingress-sg"
  description = "DEMONSTRATION ONLY: Deliberately permissive security group for CI/CD CSPM gatekeeping demonstration"
  vpc_id      = aws_vpc.soc_vpc.id

  # CRITICAL FLAW 1: SSH (Port 22) exposed to the entire public internet (0.0.0.0/0)
  ingress {
    description = "VULNERABILITY: Public SSH access open to entire world"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # Checkov CKV_AWS_24 violation
  }

  # CRITICAL FLAW 2: All TCP traffic allowed from any source IP
  ingress {
    description = "VULNERABILITY: Unrestricted ingress from all internet hosts"
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # Checkov CKV_AWS_260 violation
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    SecurityAudit = "CSPM-Test-Vulnerable-Target"
    IntentionalRisk = "True"
  }
}
