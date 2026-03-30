# Private DNS Zone for PostgreSQL
resource "azurerm_private_dns_zone" "postgresql" {
  name                = "postgres.database.azure.com"
  resource_group_name = azurerm_resource_group.main.name
  tags                = local.common_tags
}

resource "azurerm_private_dns_zone_virtual_network_link" "postgresql" {
  name                  = "vnetlink-postgresql-${var.environment}"
  private_dns_zone_name = azurerm_private_dns_zone.postgresql.name
  virtual_network_id    = azurerm_virtual_network.main.id
  resource_group_name   = azurerm_resource_group.main.name
}

# Azure Database for PostgreSQL Flexible Server
resource "azurerm_postgresql_flexible_server" "main" {
  name                          = "psql-${var.project_name}-${var.environment}"
  location                      = azurerm_resource_group.main.location
  resource_group_name           = azurerm_resource_group.main.name
  administrator_login           = "psqladmin"
  administrator_password        = var.db_admin_password
  database_charset              = "UTF8"
  database_collation            = "en_US.utf8"
  sku_name                      = var.db_sku
  storage_mb                    = var.db_storage_mb
  version                       = var.db_version
  backup_retention_days         = 35
  geo_redundant_backup_enabled  = true
  zone                          = "1"
  high_availability {
    mode                      = "ZoneRedundant"
    standby_availability_zone = "2"
  }

  delegated_subnet_id             = azurerm_subnet.database.id
  private_dns_zone_id             = azurerm_private_dns_zone.postgresql.id
  public_network_access_enabled   = false

  maintenance_window {
    day_of_week  = 0
    start_hour   = 3
    start_minute = 0
  }

  tags = local.common_tags

  depends_on = [azurerm_private_dns_zone_virtual_network_link.postgresql]
}

# PostgreSQL Server Parameters
resource "azurerm_postgresql_flexible_server_configuration" "shared_preload_libraries" {
  name       = "shared_preload_libraries"
  server_id  = azurerm_postgresql_flexible_server.main.id
  value      = "pg_stat_statements"
}

resource "azurerm_postgresql_flexible_server_configuration" "max_connections" {
  name       = "max_connections"
  server_id  = azurerm_postgresql_flexible_server.main.id
  value      = "256"
}

resource "azurerm_postgresql_flexible_server_configuration" "work_mem" {
  name       = "work_mem"
  server_id  = azurerm_postgresql_flexible_server.main.id
  value      = "4096"
}

resource "azurerm_postgresql_flexible_server_configuration" "log_statement" {
  name       = "log_statement"
  server_id  = azurerm_postgresql_flexible_server.main.id
  value      = "all"
}

# PostgreSQL Database
resource "azurerm_postgresql_flexible_server_database" "pysoar" {
  name            = "pysoar"
  server_id       = azurerm_postgresql_flexible_server.main.id
  charset         = "UTF8"
  collation       = "en_US.utf8"
}

# Azure Cache for Redis
resource "azurerm_redis_cache" "main" {
  name                = "redis-${var.project_name}-${var.environment}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  capacity            = var.redis_capacity
  family              = var.redis_family
  sku_name            = var.redis_sku
  enable_non_ssl_port = false
  minimum_tls_version = "1.2"
  tags                = local.common_tags

  redis_configuration {
    aof_backup_enabled = true
    maxmemory_policy   = "allkeys-lru"
  }

  depends_on = [azurerm_subnet_network_security_group_association.redis]
}

# Private Endpoint for Redis
resource "azurerm_private_endpoint" "redis" {
  name                = "pep-redis-${var.environment}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  subnet_id           = azurerm_subnet.redis.id

  private_service_connection {
    name                           = "psc-redis-${var.environment}"
    private_connection_resource_id = azurerm_redis_cache.main.id
    subresource_names              = ["redisCache"]
    is_manual_connection           = false
  }

  private_dns_zone_group {
    name                 = "redis-dns-group"
    private_dns_zone_ids = [azurerm_private_dns_zone.redis.id]
  }

  tags = local.common_tags
}

# Private DNS Zone for Redis
resource "azurerm_private_dns_zone" "redis" {
  name                = "redis.azure.com"
  resource_group_name = azurerm_resource_group.main.name
  tags                = local.common_tags
}

resource "azurerm_private_dns_zone_virtual_network_link" "redis" {
  name                  = "vnetlink-redis-${var.environment}"
  private_dns_zone_name = azurerm_private_dns_zone.redis.name
  virtual_network_id    = azurerm_virtual_network.main.id
  resource_group_name   = azurerm_resource_group.main.name
}

# Firewall rule for Redis (allow AKS subnet)
resource "azurerm_redis_firewall_rule" "aks" {
  name              = "allow-aks-${var.environment}"
  redis_cache_name  = azurerm_redis_cache.main.name
  resource_group_name = azurerm_resource_group.main.name
  start_ip          = split("/", var.aks_subnet_cidr)[0]
  end_ip            = cidrhost(var.aks_subnet_cidr, -1)
}
