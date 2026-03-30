variable "project_name" {
  description = "Project name for resource naming and tagging"
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

variable "azure_region" {
  description = "Azure region for resource deployment"
  type        = string
  default     = "eastus"
  validation {
    condition     = can(regex("^[a-z0-9]+$", var.azure_region))
    error_message = "Azure region must be a valid Azure region name."
  }
}

variable "resource_group_name" {
  description = "Name of the Azure resource group"
  type        = string
  validation {
    condition     = can(regex("^rg-[a-z0-9-]{1,}$", var.resource_group_name))
    error_message = "Resource group name must start with 'rg-' followed by lowercase alphanumeric characters and hyphens."
  }
}

# Network variables
variable "vnet_cidr" {
  description = "CIDR block for the virtual network"
  type        = string
  default     = "10.0.0.0/16"
}

variable "aks_subnet_cidr" {
  description = "CIDR block for AKS subnet"
  type        = string
  default     = "10.0.1.0/24"
}

variable "db_subnet_cidr" {
  description = "CIDR block for database subnet"
  type        = string
  default     = "10.0.2.0/24"
}

variable "redis_subnet_cidr" {
  description = "CIDR block for Redis subnet"
  type        = string
  default     = "10.0.3.0/24"
}

# AKS variables
variable "aks_node_count" {
  description = "Initial number of AKS nodes"
  type        = number
  default     = 3
  validation {
    condition     = var.aks_node_count >= 1 && var.aks_node_count <= 100
    error_message = "AKS node count must be between 1 and 100."
  }
}

variable "aks_node_vm_size" {
  description = "VM size for AKS nodes"
  type        = string
  default     = "Standard_D2s_v3"
}

variable "aks_kubernetes_version" {
  description = "Kubernetes version for AKS cluster"
  type        = string
  validation {
    condition     = can(regex("^\\d+\\.\\d+\\.\\d+$", var.aks_kubernetes_version))
    error_message = "Kubernetes version must be in format X.Y.Z."
  }
}

# Database variables
variable "db_sku" {
  description = "SKU for Azure Database for PostgreSQL"
  type        = string
  default     = "B_Standard_B1ms"
}

variable "db_storage_mb" {
  description = "Storage size in MB for PostgreSQL"
  type        = number
  default     = 32768
  validation {
    condition     = var.db_storage_mb >= 32768
    error_message = "Database storage must be at least 32768 MB."
  }
}

variable "db_version" {
  description = "PostgreSQL version"
  type        = string
  default     = "16"
}

variable "db_admin_username" {
  description = "Admin username for PostgreSQL"
  type        = string
  sensitive   = true
}

variable "db_admin_password" {
  description = "Admin password for PostgreSQL"
  type        = string
  sensitive   = true
}

# Redis variables
variable "redis_sku" {
  description = "SKU for Azure Cache for Redis"
  type        = string
  default     = "Standard"
  validation {
    condition     = contains(["Basic", "Standard", "Premium"], var.redis_sku)
    error_message = "Redis SKU must be Basic, Standard, or Premium."
  }
}

variable "redis_family" {
  description = "Redis family (C for Standard/Basic, P for Premium)"
  type        = string
  default     = "C"
}

variable "redis_capacity" {
  description = "Redis capacity (0 for C0, 1 for C1, etc.)"
  type        = number
  default     = 1
}

# Domain and security variables
variable "domain_name" {
  description = "Domain name for the application"
  type        = string
  validation {
    condition     = can(regex("^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$", var.domain_name))
    error_message = "Domain name must be a valid domain format."
  }
}

variable "enable_waf" {
  description = "Enable Web Application Firewall"
  type        = bool
  default     = true
}

variable "tags" {
  description = "Additional tags to apply to resources"
  type        = map(string)
  default     = {}
}
