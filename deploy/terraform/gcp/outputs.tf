output "network_name" {
  description = "Name of the VPC network"
  value       = google_compute_network.main.name
}

output "network_self_link" {
  description = "Self link of the VPC network"
  value       = google_compute_network.main.self_link
}

output "subnet_name" {
  description = "Name of the subnet"
  value       = google_compute_subnetwork.main.name
}

output "subnet_self_link" {
  description = "Self link of the subnet"
  value       = google_compute_subnetwork.main.self_link
}

output "gke_cluster_name" {
  description = "GKE cluster name"
  value       = google_container_cluster.primary.name
}

output "gke_cluster_id" {
  description = "GKE cluster ID"
  value       = google_container_cluster.primary.id
}

output "gke_endpoint" {
  description = "Endpoint of the GKE cluster"
  value       = google_container_cluster.primary.endpoint
  sensitive   = true
}

output "gke_region" {
  description = "Region of the GKE cluster"
  value       = google_container_cluster.primary.location
}

output "gke_primary_node_pool_name" {
  description = "Name of the primary GKE node pool"
  value       = google_container_node_pool.primary_nodes.name
}

output "gke_workload_node_pool_name" {
  description = "Name of the workload GKE node pool"
  value       = google_container_node_pool.workload_nodes.name
}

output "gke_service_account_email" {
  description = "Email of the GKE service account"
  value       = google_service_account.gke_nodes.email
}

output "cloud_sql_instance_name" {
  description = "Cloud SQL instance name"
  value       = google_sql_database_instance.postgres.name
}

output "cloud_sql_instance_connection_name" {
  description = "Cloud SQL instance connection name for Cloud SQL proxy"
  value       = google_sql_database_instance.postgres.connection_name
}

output "cloud_sql_private_ip_address" {
  description = "Private IP address of the Cloud SQL instance"
  value       = google_sql_database_instance.postgres.private_ip_address
}

output "cloud_sql_database_name" {
  description = "Cloud SQL database name"
  value       = google_sql_database.pysoar.name
}

output "cloud_sql_database_version" {
  description = "Cloud SQL PostgreSQL version"
  value       = google_sql_database_instance.postgres.database_version
}

output "cloud_sql_admin_username" {
  description = "Cloud SQL admin username"
  value       = google_sql_user.postgres.name
}

output "redis_instance_name" {
  description = "Memorystore Redis instance name"
  value       = google_redis_instance.cache.name
}

output "redis_instance_id" {
  description = "Memorystore Redis instance ID"
  value       = google_redis_instance.cache.id
}

output "redis_host" {
  description = "Memorystore Redis host (IP address)"
  value       = google_redis_instance.cache.host
}

output "redis_port" {
  description = "Memorystore Redis port"
  value       = google_redis_instance.cache.port
}

output "redis_auth_enabled" {
  description = "Whether Redis authentication is enabled"
  value       = google_redis_instance.cache.auth_enabled
}

output "redis_auth_token_secret_name" {
  description = "Secret Manager secret name for Redis auth token"
  value       = google_secret_manager_secret.redis_auth_token.id
}

output "cloudsql_proxy_service_account_email" {
  description = "Email of the Cloud SQL Proxy service account"
  value       = google_service_account.cloudsql_proxy.email
}

output "gke_get_credentials_command" {
  description = "Command to get GKE credentials"
  value       = "gcloud container clusters get-credentials ${google_container_cluster.primary.name} --region ${google_container_cluster.primary.location} --project ${var.project_id}"
}

output "kubectl_context_command" {
  description = "Command to set kubectl context"
  value       = "kubectl config use-context gke_${var.project_id}_${google_container_cluster.primary.location}_${google_container_cluster.primary.name}"
}

output "project_id" {
  description = "GCP project ID"
  value       = var.project_id
}

output "region" {
  description = "GCP region"
  value       = var.gcp_region
}
