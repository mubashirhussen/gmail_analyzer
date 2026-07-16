# GuardianMail — AWS infrastructure (Module 12)
# Minimum viable single-region stack: VPC (default), EC2 app host,
# S3 evidence bucket, IAM instance profile, Secrets Manager, CloudWatch.
# For multi-AZ HA extend with an ALB + Auto Scaling Group.

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.60" }
  }
}

provider "aws" {
  region = var.region
  default_tags {
    tags = {
      project     = "guardianmail"
      environment = var.environment
      managed_by  = "terraform"
    }
  }
}

variable "region"      { type = string  default = "ap-south-1" }
variable "environment" { type = string  default = "prod" }
variable "instance_type" { type = string default = "t3.large" }
variable "key_name"    { type = string }
variable "allowed_ssh_cidr" { type = string default = "0.0.0.0/0" }
variable "evidence_bucket_name" { type = string }

# ---- Networking (uses default VPC — extend for prod HA) --------------------
data "aws_vpc" "default" { default = true }
data "aws_subnets" "default" {
  filter { name = "vpc-id" values = [data.aws_vpc.default.id] }
}

resource "aws_security_group" "app" {
  name        = "gm-${var.environment}-app"
  description = "GuardianMail API + Nginx"
  vpc_id      = data.aws_vpc.default.id

  ingress { description = "HTTPS"    from_port = 443 to_port = 443 protocol = "tcp" cidr_blocks = ["0.0.0.0/0"] }
  ingress { description = "HTTP"     from_port = 80  to_port = 80  protocol = "tcp" cidr_blocks = ["0.0.0.0/0"] }
  ingress { description = "SSH"      from_port = 22  to_port = 22  protocol = "tcp" cidr_blocks = [var.allowed_ssh_cidr] }
  egress  { from_port = 0 to_port = 0 protocol = "-1" cidr_blocks = ["0.0.0.0/0"] }
}

# ---- IAM ------------------------------------------------------------------
data "aws_iam_policy_document" "assume_ec2" {
  statement {
    actions = ["sts:AssumeRole"]
    principals { type = "Service" identifiers = ["ec2.amazonaws.com"] }
  }
}

resource "aws_iam_role" "app" {
  name               = "gm-${var.environment}-app"
  assume_role_policy = data.aws_iam_policy_document.assume_ec2.json
}

resource "aws_iam_role_policy" "app" {
  name = "gm-${var.environment}-app-inline"
  role = aws_iam_role.app.id
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      { Effect = "Allow", Action = ["s3:GetObject","s3:PutObject","s3:DeleteObject","s3:ListBucket"],
        Resource = [aws_s3_bucket.evidence.arn, "${aws_s3_bucket.evidence.arn}/*"] },
      { Effect = "Allow", Action = ["secretsmanager:GetSecretValue"],
        Resource = aws_secretsmanager_secret.app.arn },
      { Effect = "Allow", Action = ["logs:CreateLogGroup","logs:CreateLogStream","logs:PutLogEvents","logs:DescribeLogStreams"],
        Resource = "*" },
      { Effect = "Allow", Action = ["cloudwatch:PutMetricData"], Resource = "*" }
    ]
  })
}

resource "aws_iam_instance_profile" "app" {
  name = "gm-${var.environment}-app"
  role = aws_iam_role.app.name
}

# ---- Storage --------------------------------------------------------------
resource "aws_s3_bucket" "evidence" {
  bucket        = var.evidence_bucket_name
  force_destroy = false
}

resource "aws_s3_bucket_versioning" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } }
}

resource "aws_s3_bucket_public_access_block" "evidence" {
  bucket                  = aws_s3_bucket.evidence.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  rule {
    id     = "expire-tmp"
    status = "Enabled"
    filter { prefix = "tmp/" }
    expiration { days = 7 }
  }
  rule {
    id     = "transition-cold"
    status = "Enabled"
    filter { prefix = "evidence/" }
    transition { days = 60 storage_class = "STANDARD_IA" }
    transition { days = 180 storage_class = "GLACIER" }
  }
}

# ---- Secrets --------------------------------------------------------------
resource "aws_secretsmanager_secret" "app" {
  name                    = "gm/${var.environment}/app"
  recovery_window_in_days = 7
}

# ---- Logging --------------------------------------------------------------
resource "aws_cloudwatch_log_group" "app" {
  name              = "/gm/${var.environment}/app"
  retention_in_days = 30
}

# ---- EC2 App Host ---------------------------------------------------------
data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical
  filter { name = "name" values = ["ubuntu/images/hvm-ssd-gp3/ubuntu-jammy-22.04-amd64-server-*"] }
}

resource "aws_instance" "app" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.instance_type
  key_name               = var.key_name
  subnet_id              = data.aws_subnets.default.ids[0]
  vpc_security_group_ids = [aws_security_group.app.id]
  iam_instance_profile   = aws_iam_instance_profile.app.name
  root_block_device      { volume_size = 40 volume_type = "gp3" encrypted = true }
  user_data = <<-EOT
    #!/usr/bin/env bash
    set -euo pipefail
    apt-get update && apt-get install -y docker.io docker-compose-plugin awscli
    systemctl enable --now docker
    mkdir -p /opt/guardianmail
    echo "provisioned $(date -u)" > /opt/guardianmail/PROVISIONED
  EOT
  tags = { Name = "gm-${var.environment}-app" }
}

resource "aws_eip" "app" {
  instance = aws_instance.app.id
  domain   = "vpc"
}

# ---- Outputs --------------------------------------------------------------
output "app_public_ip"      { value = aws_eip.app.public_ip }
output "evidence_bucket"    { value = aws_s3_bucket.evidence.bucket }
output "app_secret_arn"     { value = aws_secretsmanager_secret.app.arn }
output "log_group_name"     { value = aws_cloudwatch_log_group.app.name }
