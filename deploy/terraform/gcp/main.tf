terraform {
  required_version = ">= 1.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
    google-beta = {
      source  = "hashicorp/google-beta"
      version = "~> 5.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.0"
    }
  }

  # Uncomment for remote backend
  # backend "gcs" {
  #   bucket  = "terraform-state-bucket"
  #   prefix  = "pysoar"
  # }
}

provider "google" {
  project = var.project_id
  region  = var.gcp_region
}

provider "google-beta" {
  project = var.project_id
  region  = var.gcp_region
}

# Get current GCP context
data "google_client_config" "current" {}

# Local values for labels
locals {
  common_labels = merge(
    var.labels,
    {
      project     = var.project_name
      environment = var.environment
      managed-by  = "terraform"
    }
  )
}
