# PySOAR-specific variables - add these to your dev environment

variable "pysoar_key_pair_name" {
  description = "EC2 key pair name for SSH access to PySOAR instance"
  type        = string
}

variable "pysoar_ssh_allowed_cidrs" {
  description = "Your IP address for SSH access e.g. [\"1.2.3.4/32\"]"
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "pysoar_admin_email" {
  description = "PySOAR admin login email"
  type        = string
}

variable "pysoar_admin_password" {
  description = "PySOAR admin login password"
  type        = string
  sensitive   = true
}

variable "pysoar_secret_key" {
  description = "PySOAR app secret key - generate with: python -c \"import secrets; print(secrets.token_urlsafe(64))\""
  type        = string
  sensitive   = true
}

variable "pysoar_jwt_secret_key" {
  description = "PySOAR JWT secret key - generate with: python -c \"import secrets; print(secrets.token_urlsafe(64))\""
  type        = string
  sensitive   = true
}

variable "pysoar_db_password" {
  description = "PostgreSQL password for PySOAR"
  type        = string
  sensitive   = true
}
