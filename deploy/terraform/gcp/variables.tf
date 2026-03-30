variable "project_id" {
  description = "GCP project ID"
  type        = string
  validation {
    condition     = can(regex("^[a-z0-9-]{6,30}$", var.project_id))
    error_message = "Project ID must be 6-30 characters, lowercase alphanumeric and hyphens only."
  }
}

variable "project_name" {
  description = "Project name for resource naming and labeling"
  type        = string
  validation {
    condition     = can(regex("^[a-z0-9-]{3,20}$", var.project_name))
    error_message = "Project name must be 3-20 characters, lowercase alphanumeric and hyphens only."
  }
}

variable "environment" {
  description = "Environment name (e.g., dev, staging, prod)"
  type        = string
  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be dev, staging, or prod."
  }
}

variable "gcp_region" {
  description = "GCP region for resource deployment"
  type        = string
  default     = "us-central1"
  validation {
    condition     = can(regex("^[a-z]+-[a-z]+\\d+$", var.gcp_region))
    error_message = "GCP region must be a valid region format."
  }
}

# Network variables
variable "network_name" {
  description = "Name of the VPC network"
  type        = string
  default     = "vpc-pysoar"
}

variable "subnet_cidr" {
  description = "CIDR block for the subnet"
  type        = string
  default     = "10.0.0.0/24"
}

variable "pods_cidr" {
  description = "CIDR block for GKE pods"
  type        = string
  default     = "10.4.0.0/14"
}

variable "services_cidr" {
  description = "CIDR block for GKE services"
  type        = string
  default     = "10.8.0.0/20"
}

# GKE variables
variable "gke_node_count" {
  description = "Initial number of GKE nodes"
  type        = number
  default     = 3
  validation {
    condition     = var.gke_node_count >= 1 && var.gke_node_count <= 100
    error_message = "GKE node count must be between 1 and 100."
  }
}

variable "gke_machine_type" {
  description = "Machine type for GKE nodes"
  type        = string
  default     = "e2-standard-4"
}

variable "gke_version" {
  description = "Kubernetes version for GKE cluster"
  type        = string
  validation {
    condition     = can(regex("^\\d+\\.\\d+\\.\\d+$", var.gke_version))
    error_message = "Kubernetes version must be in format X.Y.Z."
  }
}

variable "gke_release_channel" {
  description = "GKE release channel (UNSPECIFIED, RAPID, REGULAR, STABLE)"
  type        = string
  default     = "REGULAR"
  validation {
    condition     = contains(["UNSPECIFIED", "RAPID", "REGULAR", "STABLE"], var.gke_release_channel)
    error_message = "GKE release channel must be UNSPECIFIED, RAPID, REGULAR, or STABLE."
  }
}

# Cloud SQL variables
variable "db_tier" {
  description = "Machine type for Cloud SQL instance"
  type        = string
  default     = "db-custom-2-8192"
}

variable "db_version" {
  description = "PostgreSQL version"
  type        = string
  default     = "POSTGRES_16"
}

variable "db_disk_size" {
  description = "Storage size in GB for Cloud SQL"
  type        = number
  default     = 100
  validation {
    condition     = var.db_disk_size >= 20
    error_message = "Database storage must be at least 20 GB."
  }
}

variable "db_admin_user" {
  description = "Admin user for Cloud SQL"
  type        = string
  default     = "postgres"
  sensitive   = true
}

variable "db_admin_password" {
  description = "Admin password for Cloud SQL"
  type        = string
  sensitive   = true
}

variable "db_backup_location" {
  description = "Location for Cloud SQL backups"
  type        = string
  default     = "us"
}

# Memorystore Redis variables
variable "redis_tier" {
  description = "Tier for Memorystore Redis (BASIC, STANDARD_HA)"
  type        = string
  default     = "STANDARD_HA"
  validation {
    condition     = contains(["BASIC", "STANDARD_HA"], var.redis_tier)
    error_message = "Redis tier must be BASIC or STANDARD_HA."
  }
}

variable "redis_memory_gb" {
  description = "Memory size in GB for Memorystore Redis"
  type        = number
  default     = 4
  validation {
    condition     = var.redis_memory_gb >= 1 && var.redis_memory_gb <= 300
    error_message = "Redis memory must be between 1 and 300 GB."
  }
}

variable "redis_version" {
  description = "Redis version"
  type        = string
  default     = "redis_7_x"
}

# Security variables
variable "domain_name" {
  description = "Domain name for the application"
  type        = string
  validation {
    condition     = can(regex("^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$", var.domain_name))
    error_message = "Domain name must be a valid domain format."
  }
}

variable "enable_armor" {
  description = "Enable Google Cloud Armor for DDoS protection"
  type        = bool
  default     = true
}

variable "labels" {
  description = "Additional labels to apply to resources"
  type        = map(string)
  default     = {}
}
