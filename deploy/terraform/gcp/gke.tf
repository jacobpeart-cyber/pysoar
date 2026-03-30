# Service account for GKE nodes
resource "google_service_account" "gke_nodes" {
  account_id   = "sa-gke-${var.project_name}-${var.environment}"
  display_name = "Service account for GKE nodes"
  description  = "Service account for ${var.project_name} ${var.environment} GKE nodes"
}

# Grant necessary permissions to the service account
resource "google_project_iam_member" "gke_log_writer" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.gke_nodes.email}"
}

resource "google_project_iam_member" "gke_metric_writer" {
  project = var.project_id
  role    = "roles/monitoring.metricWriter"
  member  = "serviceAccount:${google_service_account.gke_nodes.email}"
}

resource "google_project_iam_member" "gke_metric_viewer" {
  project = var.project_id
  role    = "roles/monitoring.viewer"
  member  = "serviceAccount:${google_service_account.gke_nodes.email}"
}

# GKE Cluster
resource "google_container_cluster" "primary" {
  name     = "gke-${var.project_name}-${var.environment}"
  location = var.gcp_region
  project  = var.project_id

  # We can't create a cluster with no node pool defined, but we want to only use
  # separately managed node pools. So we create the smallest possible default
  # node pool and immediately delete it.
  remove_default_node_pool = true
  initial_node_count       = 1

  network    = google_compute_network.main.name
  subnetwork = google_compute_subnetwork.main.name

  # GKE configuration
  enable_ip_alias                     = true
  cluster_secondary_range_name         = "pods"
  services_secondary_range_name        = "services"
  min_master_version                  = var.gke_version
  enable_shielded_nodes               = true
  enable_network_policy               = true
  enable_vertical_pod_autoscaling     = true
  enable_intra_node_visibility        = true

  # Security
  enable_binary_authorization = true

  # Release channel
  release_channel {
    channel = var.gke_release_channel
  }

  # Logging and monitoring
  logging_service    = "logging.googleapis.com/kubernetes"
  monitoring_service = "monitoring.googleapis.com/kubernetes"

  # Network policy
  network_policy {
    enabled  = true
    provider = "CALICO"
  }

  # Workload Identity
  workload_identity_config {
    workload_pool = "${var.project_id}.svc.id.goog"
  }

  # Maintenance window
  maintenance_policy {
    daily_maintenance_window {
      start_time = "03:00"
    }
  }

  # Cluster resource labels
  resource_labels = local.common_labels

  # Cluster addons
  addons_config {
    http_load_balancing {
      disabled = false
    }
    horizontal_pod_autoscaling {
      disabled = false
    }
    network_policy_config {
      disabled = false
    }
    gce_persistent_disk_csi_driver_config {
      enabled = true
    }
    config_connector_config {
      enabled = true
    }
  }

  # Cluster API scopes
  ip_allocation_policy {
    cluster_secondary_range_name  = "pods"
    services_secondary_range_name = "services"
  }

  depends_on = [
    google_service_networking_connection.private_vpc_connection
  ]
}

# GKE Node Pool
resource "google_container_node_pool" "primary_nodes" {
  name       = "primary"
  location   = var.gcp_region
  cluster    = google_container_cluster.primary.name
  project    = var.project_id
  node_count = var.gke_node_count

  autoscaling {
    min_node_count = var.gke_node_count
    max_node_count = var.gke_node_count * 2
  }

  management {
    auto_repair  = true
    auto_upgrade = true
  }

  node_config {
    preemptible  = false
    machine_type = var.gke_machine_type

    disk_size_gb = 100
    disk_type    = "pd-standard"

    # Google recommends custom service accounts that have cloud-platform scope and permissions granted via IAM Roles.
    service_account = google_service_account.gke_nodes.email
    oauth_scopes = [
      "https://www.googleapis.com/auth/cloud-platform"
    ]

    # Shielded instance
    shielded_instance_config {
      enable_secure_boot          = true
      enable_integrity_monitoring = true
    }

    # Workload Identity
    workload_metadata_config {
      mode = "GKE_METADATA"
    }

    # Node pool labels and taints
    labels = merge(
      local.common_labels,
      {
        "node-pool" = "primary"
      }
    )

    tags = ["gke-node", "${var.project_name}-${var.environment}"]

    metadata = {
      disable-legacy-endpoints = "true"
    }
  }

  node_locations = [
    "${var.gcp_region}-a",
    "${var.gcp_region}-b",
    "${var.gcp_region}-c",
  ]
}

# GKE Node Pool for workloads
resource "google_container_node_pool" "workload_nodes" {
  name    = "workload"
  cluster = google_container_cluster.primary.name
  project = var.project_id

  autoscaling {
    min_node_count = var.gke_node_count
    max_node_count = var.gke_node_count * 2
  }

  management {
    auto_repair  = true
    auto_upgrade = true
  }

  node_config {
    preemptible  = false
    machine_type = var.gke_machine_type

    disk_size_gb = 100
    disk_type    = "pd-standard"

    service_account = google_service_account.gke_nodes.email
    oauth_scopes = [
      "https://www.googleapis.com/auth/cloud-platform"
    ]

    # Shielded instance
    shielded_instance_config {
      enable_secure_boot          = true
      enable_integrity_monitoring = true
    }

    # Workload Identity
    workload_metadata_config {
      mode = "GKE_METADATA"
    }

    # Node pool labels and taints
    labels = merge(
      local.common_labels,
      {
        "node-pool" = "workload"
      }
    )

    taint {
      key    = "workload"
      value  = "true"
      effect = "NO_SCHEDULE"
    }

    tags = ["gke-node", "${var.project_name}-${var.environment}"]

    metadata = {
      disable-legacy-endpoints = "true"
    }
  }

  node_locations = [
    "${var.gcp_region}-a",
    "${var.gcp_region}-b",
    "${var.gcp_region}-c",
  ]
}

# Configure Kubernetes provider
provider "kubernetes" {
  host                   = "https://${google_container_cluster.primary.endpoint}"
  token                  = data.google_client_config.current.access_token
  cluster_ca_certificate = base64decode(google_container_cluster.primary.master_auth[0].cluster_ca_certificate)
}
