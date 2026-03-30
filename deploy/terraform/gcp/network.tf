# VPC Network
resource "google_compute_network" "main" {
  name                    = var.network_name
  auto_create_subnetworks = false
  description             = "VPC network for ${var.project_name}-${var.environment}"
  routing_mode            = "REGIONAL"
}

# Subnet with secondary ranges for GKE
resource "google_compute_subnetwork" "main" {
  name          = "subnet-${var.project_name}-${var.environment}"
  ip_cidr_range = var.subnet_cidr
  region        = var.gcp_region
  network       = google_compute_network.main.id
  description   = "Subnet for ${var.project_name} ${var.environment}"

  private_ip_google_access = true
  enable_flow_logs         = true

  flow_logs_config {
    enable        = true
    sampling_rate = 0.5
    metadata      = "INCLUDE_ALL_METADATA"
  }

  secondary_ip_range {
    range_name    = "pods"
    ip_cidr_range = var.pods_cidr
  }

  secondary_ip_range {
    range_name    = "services"
    ip_cidr_range = var.services_cidr
  }
}

# Cloud Router for Cloud NAT
resource "google_compute_router" "main" {
  name    = "router-${var.project_name}-${var.environment}"
  region  = var.gcp_region
  network = google_compute_network.main.id

  bgp {
    asn = 64514
  }
}

# Cloud NAT for outbound traffic
resource "google_compute_router_nat" "main" {
  name                               = "nat-${var.project_name}-${var.environment}"
  router                             = google_compute_router.main.name
  region                             = google_compute_router.main.region
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"
  enable_dynamic_port_allocation     = true
  enable_endpoint_independent_mapping = true

  log_config {
    enable = true
    filter = "ERRORS_ONLY"
  }
}

# Firewall rule - allow internal traffic
resource "google_compute_firewall" "internal" {
  name    = "fw-${var.project_name}-internal"
  network = google_compute_network.main.name

  allow {
    protocol = "tcp"
    ports    = ["0-65535"]
  }

  allow {
    protocol = "udp"
    ports    = ["0-65535"]
  }

  allow {
    protocol = "icmp"
  }

  source_ranges = [var.subnet_cidr, var.pods_cidr]
}

# Firewall rule - allow GCP health checks
resource "google_compute_firewall" "health_checks" {
  name    = "fw-${var.project_name}-health-checks"
  network = google_compute_network.main.name

  allow {
    protocol = "tcp"
  }

  source_ranges = ["35.191.0.0/16", "130.211.0.0/22"]
}

# Firewall rule - allow IAP SSH access
resource "google_compute_firewall" "iap_ssh" {
  name    = "fw-${var.project_name}-iap-ssh"
  network = google_compute_network.main.name

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_ranges = ["35.235.240.0/20"]
}

# Firewall rule - allow HTTPS ingress
resource "google_compute_firewall" "https" {
  name    = "fw-${var.project_name}-https"
  network = google_compute_network.main.name

  allow {
    protocol = "tcp"
    ports    = ["443"]
  }

  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["https-server"]
}

# Firewall rule - allow HTTP ingress
resource "google_compute_firewall" "http" {
  name    = "fw-${var.project_name}-http"
  network = google_compute_network.main.name

  allow {
    protocol = "tcp"
    ports    = ["80"]
  }

  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["http-server"]
}

# Private service access for Cloud SQL
resource "google_compute_global_address" "private_service_access" {
  name          = "psa-${var.project_name}-${var.environment}"
  purpose       = "VPC_PEERING"
  address_type  = "INTERNAL"
  prefix_length = 16
  network       = google_compute_network.main.id
}

resource "google_service_networking_connection" "private_vpc_connection" {
  network                 = google_compute_network.main.id
  service                 = "servicenetworking.googleapis.com"
  reserved_peering_ranges = [google_compute_global_address.private_service_access.name]
}
