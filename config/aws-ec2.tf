# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 yonasBSD

terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
    }
  }
}

provider "aws" {
  alias   = "user"
  region  = var.region
  profile = var.profile
}

resource "aws_security_group" "instance" {
  name = "tf-test"

  # Inbound HTTP from anywhere
  ingress {
    from_port   = var.server_port
    to_port     = var.server_port
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Inbound SSH from management ip
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.mgmt_ip]
  }

  # Outbound web for package downloading
  egress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Outbound web for package downloading
  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = var.server_port
    to_port     = var.server_port
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}


resource "aws_instance" "example" {
  ami           = var.ami_tamu_ubuntu
  instance_type = var.instance_type
  vpc_security_group_ids = [aws_security_group.instance.id]
  associate_public_ip_address = false

  metadata_options = {
    http_endpoint = "enabled"
    http_tokens = "required"
  }

  tags = {
    Name = "EC2EXAMPLE"
  }

}
