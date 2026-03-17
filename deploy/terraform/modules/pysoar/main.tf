# PySOAR Module - EC2 Instance + Security Group + Elastic IP
# Deploys PySOAR into an existing VPC public subnet

# -------------------------------------------------------
# Data Sources
# -------------------------------------------------------

# Latest Ubuntu 22.04 LTS AMI (ARM or x86 depending on instance type)
data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# -------------------------------------------------------
# Security Group
# -------------------------------------------------------

resource "aws_security_group" "pysoar" {
  name        = "${var.project_name}-${var.environment}-pysoar-sg"
  description = "PySOAR SOAR Platform security group"
  vpc_id      = var.vpc_id

  # HTTP
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTP"
  }

  # HTTPS
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTPS"
  }

  # SSH
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.ssh_allowed_cidrs
    description = "SSH access"
  }

  # All outbound traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "All outbound traffic"
  }

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-pysoar-sg"
  })
}

# -------------------------------------------------------
# EC2 Instance
# -------------------------------------------------------

resource "aws_instance" "pysoar" {
  ami                         = data.aws_ami.ubuntu.id
  instance_type               = var.instance_type
  subnet_id                   = var.public_subnet_id
  vpc_security_group_ids      = [aws_security_group.pysoar.id]
  key_name                    = var.key_pair_name
  associate_public_ip_address = true

  root_block_device {
    volume_size           = var.root_volume_size
    volume_type           = "gp3"
    encrypted             = true
    delete_on_termination = true

    tags = merge(var.tags, {
      Name = "${var.project_name}-${var.environment}-pysoar-root"
    })
  }

  user_data = base64encode(templatefile("${path.module}/userdata.sh", {
    pysoar_repo          = var.pysoar_repo_url
    admin_email          = var.admin_email
    admin_password       = var.admin_password
    secret_key           = var.secret_key
    jwt_secret_key       = var.jwt_secret_key
    db_password          = var.db_password
    cors_origins         = var.cors_origins
  }))

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-pysoar"
  })
}

# -------------------------------------------------------
# Elastic IP (stable public IP that doesn't change on reboot)
# -------------------------------------------------------

resource "aws_eip" "pysoar" {
  instance = aws_instance.pysoar.id
  domain   = "vpc"

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-pysoar-eip"
  })
}

# -------------------------------------------------------
# CloudWatch Log Group for PySOAR logs
# -------------------------------------------------------

resource "aws_cloudwatch_log_group" "pysoar" {
  name              = "/pysoar/${var.environment}"
  retention_in_days = var.log_retention_days

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-pysoar-logs"
  })
}
