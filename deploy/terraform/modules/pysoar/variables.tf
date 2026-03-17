# PySOAR Module Variables

variable "project_name" {
  description = "Name of the project"
  type        = string
}

variable "environment" {
  description = "Environment name"
  type        = string
}

variable "vpc_id" {
  description = "VPC ID to deploy PySOAR into"
  type        = string
}

variable "public_subnet_id" {
  description = "Public subnet ID for the PySOAR instance"
  type        = string
}

variable "key_pair_name" {
  description = "EC2 key pair name for SSH access"
  type        = string
}

variable "instance_type" {
  description = "EC2 instance type (t3.medium minimum recommended)"
  type        = string
  default     = "t3.medium"
}

variable "root_volume_size" {
  description = "Root EBS volume size in GB"
  type        = number
  default     = 30
}

variable "ssh_allowed_cidrs" {
  description = "CIDR blocks allowed to SSH into the instance"
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "pysoar_repo_url" {
  description = "Git repository URL for PySOAR"
  type        = string
  default     = "https://github.com/jacobpeart-cyber/pysoar.git"
}

variable "admin_email" {
  description = "Initial admin user email"
  type        = string
}

variable "admin_password" {
  description = "Initial admin user password"
  type        = string
  sensitive   = true
}

variable "secret_key" {
  description = "Application secret key"
  type        = string
  sensitive   = true
}

variable "jwt_secret_key" {
  description = "JWT signing secret key"
  type        = string
  sensitive   = true
}

variable "db_password" {
  description = "PostgreSQL database password"
  type        = string
  sensitive   = true
}

variable "cors_origins" {
  description = "Allowed CORS origins as JSON array string"
  type        = string
  default     = "[\"http://localhost\"]"
}

variable "log_retention_days" {
  description = "CloudWatch log retention in days"
  type        = number
  default     = 30
}

variable "tags" {
  description = "Tags to apply to all resources"
  type        = map(string)
  default     = {}
}
