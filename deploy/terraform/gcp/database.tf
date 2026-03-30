# Cloud SQL PostgreSQL Instance
resource "google_sql_database_instance" "postgres" {
  name             = "cloudsql-${var.project_name}-${var.environment}"
  database_version = var.db_version
  region           = var.gcp_region
  project          = var.project_id

  # Create the instance, then immediately destroy the replicas to save costs
  deletion_protection = true

  settings {
    tier              = var.db_tier
    availability_type = "REGIONAL"
    disk_size         = var.db_disk_size
    disk_type         = "PD_SSD"
    disk_autoresize   = true
    disk_autoresize_limit = var.db_disk_size * 2

    # Backup configuration
    backup_configuration {
      enabled                        = true
      start_time                     = "03:00"
      point_in_time_recovery_enabled = true
      transaction_log_retention_days = 7
      backup_retention_settings {
        retained_backups = 30
        retention_unit   = "COUNT"
      }
    }

    # IP configuration - private IP only
    ip_configuration {
      ipv4_enabled                                  = false
      private_network                              = google_compute_network.main.id
      enable_private_path_for_cloudsql_cloud_sql   = true
      require_ssl                                  = true
      authorized_networks {
        name  = "gke-subnet"
        value = var.subnet_cidr
      }
    }

    # Database flags
    database_flags {
      name  = "max_connections"
      value = "256"
    }

    database_flags {
      name  = "shared_buffers"
      value = "131072"
    }

    database_flags {
      name  = "work_mem"
      value = "4096"
    }

    database_flags {
      name  = "random_page_cost"
      value = "1.1"
    }

    database_flags {
      name  = "log_statement"
      value = "all"
    }

    # Maintenance window
    maintenance_window {
      kind           = "MYSQL"
      day            = 0  # Monday
      hour           = 2
      update_track   = "stable"
    }

    # Insights configuration
    insights_config {
      query_insights_enabled  = true
      query_string_length     = 1024
      record_application_tags = true
      record_client_address  = true
    }

    # User labels
    user_labels = local.common_labels
  }

  depends_on = [
    google_service_networking_connection.private_vpc_connection
  ]
}

# Cloud SQL Database
resource "google_sql_database" "pysoar" {
  name     = "pysoar"
  instance = google_sql_database_instance.postgres.name
  project  = var.project_id
}

# Cloud SQL User
resource "google_sql_user" "postgres" {
  name     = var.db_admin_user
  instance = google_sql_database_instance.postgres.name
  password = var.db_admin_password
  project  = var.project_id
  type     = "BUILT_IN"
}

# Memorystore Redis Instance
resource "google_redis_instance" "cache" {
  name           = "redis-${var.project_name}-${var.environment}"
  tier           = var.redis_tier
  memory_size_gb = var.redis_memory_gb
  region         = var.gcp_region
  project        = var.project_id

  # Redis version
  redis_version = var.redis_version

  # Private network
  connect_mode = "PRIVATE_SERVICE_ACCESS"
  authorized_network = google_compute_network.main.id

  # High availability
  replica_configuration {
    automatic_failover = true
  }

  # Authentication
  auth_enabled = true

  # Transit encryption
  transit_encryption_mode = "SERVER_AUTHENTICATION"

  # Persistence
  persistence_config {
    persistence_mode = "RDB"
    rdb_snapshot_retention_days = 7
    rdb_snapshot_period         = "TWELVE_HOURS"
  }

  # Maintenance window
  maintenance_policy {
    day        = "MONDAY"
    start_time {
      hours   = 3
      minutes = 0
    }
  }

  # Labels
  labels = local.common_labels

  depends_on = [
    google_service_networking_connection.private_vpc_connection
  ]
}

# Redis AUTH token stored in Secret Manager
resource "google_secret_manager_secret" "redis_auth_token" {
  secret_id = "redis-auth-${var.project_name}-${var.environment}"
  project   = var.project_id

  labels = local.common_labels

  replication {
    automatic = true
  }
}

resource "google_secret_manager_secret_version" "redis_auth_token" {
  secret      = google_secret_manager_secret.redis_auth_token.id
  secret_data = google_redis_instance.cache.auth_string
  project     = var.project_id
}

# Cloud SQL proxy service account for Kubernetes
resource "google_service_account" "cloudsql_proxy" {
  account_id   = "sa-cloudsql-proxy-${var.project_name}-${var.environment}"
  display_name = "Service account for Cloud SQL Proxy"
  description  = "Service account for ${var.project_name} ${var.environment} Cloud SQL Proxy"
  project      = var.project_id
}

resource "google_project_iam_member" "cloudsql_client" {
  project = var.project_id
  role    = "roles/cloudsql.client"
  member  = "serviceAccount:${google_service_account.cloudsql_proxy.email}"
}

# Workload Identity binding for Cloud SQL Proxy
resource "google_service_account_iam_member" "cloudsql_proxy_workload_identity" {
  service_account_id = google_service_account.cloudsql_proxy.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "serviceAccount:${var.project_id}.svc.id.goog[kube-system/cloudsql-proxy]"
  project            = var.project_id
}
