# Get current Azure AD context
data "azuread_client_config" "current" {}

# AKS Cluster
resource "azurerm_kubernetes_cluster" "main" {
  name                = "aks-${var.project_name}-${var.environment}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  dns_prefix          = "${var.project_name}-${var.environment}"
  kubernetes_version  = var.aks_kubernetes_version
  node_resource_group = "rg-aks-nodes-${var.project_name}-${var.environment}"

  depends_on = [
    azurerm_subnet_nat_gateway_association.aks
  ]

  # Default system node pool
  default_node_pool {
    name                = "system"
    node_count          = var.aks_node_count
    vm_size             = var.aks_node_vm_size
    vnet_subnet_id      = azurerm_subnet.aks.id
    enable_auto_scaling = true
    min_count           = var.aks_node_count
    max_count           = var.aks_node_count + 2
    max_pods            = 110
    availability_zones  = ["1", "2", "3"]

    upgrade_settings {
      max_surge = 1
    }

    tags = local.common_tags
  }

  # Network configuration
  network_profile {
    network_plugin    = "azure"
    network_policy    = "azure"
    service_cidr      = "10.1.0.0/16"
    dns_service_ip    = "10.1.0.10"
    docker_bridge_cidr = "172.17.0.1/16"
    load_balancer_sku = "standard"

    load_balancer_profile {
      managed_outbound_ip_count = 1
    }
  }

  # Azure AD RBAC
  azure_active_directory_role_based_access_control {
    managed                = true
    tenant_id              = data.azuread_client_config.current.tenant_id
    admin_group_object_ids = []
  }

  # Monitor agent for Container Insights
  oms_agent {
    log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id
  }

  # Key Vault secrets provider
  key_vault_secrets_provider {
    secret_rotation_enabled  = true
    secret_rotation_interval = "2m"
  }

  # Auto-scaling
  auto_scaler_profile {
    balance_similar_node_groups      = false
    empty_bulk_delete_max            = 10
    expander                         = "least-waste"
    max_graceful_termination_sec     = 600
    max_node_provision_time          = "15m"
    max_total_unready_percentage     = 45
    new_pod_scale_up_delay           = "0s"
    scale_down_delay_after_add       = "10m"
    scale_down_unneeded              = "10m"
    scale_down_unready               = "20m"
    scale_down_utilization_threshold = "0.5"
    skip_nodes_with_local_storage    = true
  }

  role_based_access_control_enabled = true

  tags = local.common_tags

  lifecycle {
    ignore_changes = [
      kubernetes_cluster_system_addons_profile,
    ]
  }
}

# User node pool for workloads
resource "azurerm_kubernetes_cluster_node_pool" "workload" {
  name                  = "workload"
  kubernetes_cluster_id = azurerm_kubernetes_cluster.main.id
  node_count            = var.aks_node_count
  vm_size               = var.aks_node_vm_size
  vnet_subnet_id        = azurerm_subnet.aks.id
  enable_auto_scaling   = true
  min_count             = var.aks_node_count
  max_count             = var.aks_node_count * 2
  max_pods              = 110
  availability_zones    = ["1", "2", "3"]
  mode                  = "User"

  upgrade_settings {
    max_surge = 1
  }

  node_taints = [
    "workload=true:NoSchedule"
  ]

  tags = merge(
    local.common_tags,
    {
      NodePool = "workload"
    }
  )
}

# Log Analytics Workspace for Container Insights
resource "azurerm_log_analytics_workspace" "main" {
  name                = "law-${var.project_name}-${var.environment}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  sku                 = "PerGB2018"
  retention_in_days   = 30
  tags                = local.common_tags
}

# Diagnostic settings for AKS cluster
resource "azurerm_monitor_diagnostic_setting" "aks" {
  name                       = "diag-${var.project_name}-aks"
  target_resource_id         = azurerm_kubernetes_cluster.main.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id

  enabled_log {
    category = "kube-apiserver"
  }

  enabled_log {
    category = "kube-controller-manager"
  }

  enabled_log {
    category = "kube-scheduler"
  }

  enabled_log {
    category = "kube-audit"
  }

  metric {
    category = "AllMetrics"
  }
}

# Role assignment for AKS to access ACR (if needed)
resource "azurerm_role_assignment" "aks_pull_acr" {
  scope              = azurerm_resource_group.main.id
  role_definition_name = "AcrPull"
  principal_id       = azurerm_kubernetes_cluster.main.kubelet_identity[0].object_id
}

# Role assignment for system-assigned managed identity
resource "azurerm_role_assignment" "aks_managed_identity_operator" {
  scope              = azurerm_kubernetes_cluster.main.id
  role_definition_name = "Managed Identity Operator"
  principal_id       = azurerm_kubernetes_cluster.main.kubelet_identity[0].object_id
}
