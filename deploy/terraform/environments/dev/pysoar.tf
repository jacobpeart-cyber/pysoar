# PySOAR Deployment - Add this to your existing dev environment

module "pysoar" {
  source = "../../modules/pysoar"

  project_name     = var.project_name
  environment      = var.environment
  vpc_id           = module.vpc.vpc_id
  public_subnet_id = module.vpc.public_subnet_ids[0]
  key_pair_name    = var.pysoar_key_pair_name
  instance_type    = "t3.medium"
  root_volume_size = 30

  # Restrict SSH to your IP only (more secure than 0.0.0.0/0)
  ssh_allowed_cidrs = var.pysoar_ssh_allowed_cidrs

  # PySOAR credentials - stored in terraform.tfvars (never commit!)
  admin_email    = var.pysoar_admin_email
  admin_password = var.pysoar_admin_password
  secret_key     = var.pysoar_secret_key
  jwt_secret_key = var.pysoar_jwt_secret_key
  db_password    = var.pysoar_db_password
  cors_origins   = "[\"http://${module.pysoar.public_ip}\"]"

  tags = merge(var.additional_tags, {
    Service = "PySOAR"
  })
}

# Output the PySOAR URL after deployment
output "pysoar_url" {
  description = "PySOAR dashboard URL"
  value       = module.pysoar.pysoar_url
}

output "pysoar_ssh" {
  description = "SSH command for PySOAR instance"
  value       = module.pysoar.ssh_command
}
