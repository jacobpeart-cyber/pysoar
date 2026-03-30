# AWS Terraform Deployment for PySOAR

Production-grade AWS infrastructure as code for PySOAR (Python Security Operations Analytics & Response), a FastAPI-based SIEM platform.

## Architecture Overview

This Terraform deployment creates a complete AWS infrastructure with:

- **Container Orchestration**: Amazon EKS (Elastic Kubernetes Service)
- **Relational Database**: Amazon RDS PostgreSQL with Multi-AZ
- **Cache Layer**: Amazon ElastiCache Redis with replication
- **Networking**: VPC with public/private subnets across 3 AZs
- **Storage**: S3 buckets for logs and backups
- **Security**: KMS encryption, Secrets Manager, WAF, Security Groups
- **Monitoring**: CloudWatch logs, metrics, alarms, and dashboards
- **Access Management**: IRSA (IAM Roles for Service Accounts)

## File Structure

| File | Lines | Purpose |
|------|-------|---------|
| `main.tf` | 69 | Terraform and provider configurations, data sources |
| `variables.tf` | 176 | All input variables with validation |
| `vpc.tf` | 175 | VPC, subnets, NAT/IGW, route tables, VPC Flow Logs |
| `eks.tf` | 331 | EKS cluster, managed node group, OIDC provider, add-ons |
| `rds.tf` | 138 | RDS PostgreSQL instance, security group, parameter group |
| `elasticache.tf` | 130 | Redis replication group, security, logging |
| `s3.tf` | 177 | S3 buckets with encryption, versioning, lifecycle policies |
| `monitoring.tf` | 189 | CloudWatch logs, alarms, SNS topic, dashboard |
| `security.tf` | 252 | KMS encryption, Secrets Manager, WAF, IAM policies |
| `outputs.tf` | 176 | Output values for integration and reference |
| `terraform.tfvars.example` | 46 | Example variable values |
| **Total** | **1,859** | Complete production deployment |

## Quick Start

### Prerequisites

- Terraform >= 1.0
- AWS CLI configured with appropriate credentials
- kubectl installed for EKS access
- Helm 3.0+ (optional, for Helm chart deployments)

### Deployment Steps

1. **Clone and navigate to AWS directory**:
   ```bash
   cd deploy/terraform/aws
   ```

2. **Create terraform.tfvars**:
   ```bash
   cp terraform.tfvars.example terraform.tfvars
   # Edit terraform.tfvars with your values
   ```

3. **Initialize Terraform**:
   ```bash
   terraform init
   ```

4. **Review planned changes**:
   ```bash
   terraform plan -out=tfplan
   ```

5. **Apply configuration**:
   ```bash
   terraform apply tfplan
   ```

6. **Configure kubectl**:
   ```bash
   aws eks update-kubeconfig --region us-east-1 --name pysoar-production-eks
   ```

## Configuration Variables

### Core Settings
- `project_name`: Project identifier (default: "pysoar")
- `environment`: Deployment environment (default: "production")
- `aws_region`: AWS region (default: "us-east-1")

### VPC & Networking
- `vpc_cidr`: VPC CIDR block (default: "10.0.0.0/16")
- `availability_zones`: AZs to use (default: ["us-east-1a", "us-east-1b", "us-east-1c"])

### EKS Configuration
- `eks_cluster_version`: Kubernetes version (default: "1.29")
- `eks_node_instance_types`: Node instance types (default: ["t3.large"])
- `eks_min_nodes`: Minimum nodes (default: 2)
- `eks_max_nodes`: Maximum nodes (default: 10)
- `eks_desired_nodes`: Desired nodes (default: 3)

### RDS PostgreSQL
- `db_instance_class`: Instance type (default: "db.t3.medium")
- `db_engine_version`: PostgreSQL version (default: "16.3")
- `db_allocated_storage`: Storage in GB (default: 50)
- `db_name`: Database name (default: "pysoar")
- `db_multi_az`: Enable Multi-AZ (default: true)
- `db_backup_retention_days`: Backup retention (default: 7)

### ElastiCache Redis
- `redis_node_type`: Node type (default: "cache.t3.medium")
- `redis_num_cache_nodes`: Number of nodes (default: 2)
- `redis_snapshot_retention_limit`: Snapshot retention days (default: 5)

### Security & Features
- `enable_waf`: Enable AWS WAF (default: true)
- `enable_monitoring`: Enable CloudWatch monitoring (default: true)
- `domain_name`: Optional domain name (default: null)

## Key Features

### Security

- **Encryption**: KMS encryption at rest for RDS, ElastiCache, S3, and secrets
- **Secrets Management**: AWS Secrets Manager for database and application credentials
- **WAF Protection**: AWS Web Application Firewall with managed rules and rate limiting
- **Network Security**: VPC Flow Logs, security groups with least-privilege rules
- **IRSA**: IAM Roles for Service Accounts enable Pod-level IAM access
- **Deletion Protection**: Enabled on RDS to prevent accidental deletion

### High Availability

- **Multi-AZ**: RDS Multi-AZ deployment for automatic failover
- **Multi-Zone EKS**: Nodes spread across 3 availability zones
- **Redis Replication**: Automatic failover with primary/replica replication
- **NAT Gateway**: Single NAT for cost (production should use per-AZ NAT for HA)

### Monitoring & Logging

- **CloudWatch Logs**: EKS cluster, application, and SIEM logs with retention
- **Alarms**: RDS CPU/storage, Redis CPU/memory, EKS node count
- **Dashboard**: Unified CloudWatch dashboard for key metrics
- **Performance Insights**: RDS performance monitoring enabled
- **Slow Query Logs**: Redis slow-log delivery to CloudWatch

### Backup & Disaster Recovery

- **RDS Automated Backups**: 7-day retention with automated snapshots
- **Redis Snapshots**: 5-day retention for point-in-time recovery
- **S3 Versioning**: Enabled on backup buckets
- **S3 Lifecycle**: Transition to cheaper storage tiers
- **Final Snapshots**: Automatic snapshot on instance deletion

## Outputs

Key outputs for integration:

- `eks_cluster_name`: EKS cluster name
- `eks_cluster_endpoint`: Kubernetes API endpoint
- `rds_endpoint`: PostgreSQL endpoint
- `redis_endpoint`: Redis endpoint
- `s3_logs_bucket`: Log storage bucket
- `s3_backups_bucket`: Backup bucket
- `kms_key_arn`: Encryption key ARN
- `secrets_db_arn`: Database credentials secret ARN
- `waf_web_acl_arn`: WAF Web ACL ARN (if enabled)
- `kubeconfig_command`: Command to update kubeconfig

## Cost Optimization Notes

1. **Single NAT Gateway**: Current setup uses a single NAT for cost savings. For production HA, create a NAT per AZ (uncomment logic in vpc.tf).

2. **Instance Types**: Adjust instance classes based on workload:
   - Dev/Test: `db.t3.micro`, `cache.t3.micro`
   - Production: `db.t3.large` or larger for predictable workloads

3. **Storage**: RDS allocated storage grows automatically but has limits; plan capacity accordingly.

4. **Monitoring**: CloudWatch alarms incur minimal costs; dashboards are free.

## Post-Deployment

After deployment completes:

1. **Verify EKS connectivity**:
   ```bash
   kubectl get nodes
   kubectl get pods --all-namespaces
   ```

2. **Retrieve secrets** (stored in AWS Secrets Manager):
   ```bash
   aws secretsmanager get-secret-value \
     --secret-id pysoar/production/db-credentials \
     --region us-east-1
   ```

3. **Configure application** with database and Redis endpoints from outputs.

4. **Set up monitoring**: Configure SNS subscriptions for alert notifications.

5. **Deploy PySOAR**: Use Helm or kubectl to deploy application containers.

## Destruction

To tear down all infrastructure:

```bash
terraform destroy
```

**Warning**: This will delete:
- RDS database (final snapshot created)
- ElastiCache cluster (automatic snapshot created)
- EKS cluster and all running pods
- S3 buckets (if empty)
- VPC and all associated resources

## Troubleshooting

### EKS Addon Failures
If addon installation fails, check addon compatibility:
```bash
aws eks list-addons --cluster-name pysoar-production-eks
```

### Database Connection Issues
Verify security group rules allow traffic from EKS nodes:
```bash
aws ec2 describe-security-groups --group-ids sg-xxxxx
```

### Secrets Access
Verify IRSA role trust relationship:
```bash
aws iam get-role --role-name pysoar-production-app-secrets-role
```

## Support & Maintenance

- **Terraform Documentation**: https://registry.terraform.io/providers/hashicorp/aws/latest
- **AWS EKS Best Practices**: https://aws.github.io/aws-eks-best-practices/
- **PySOAR Documentation**: See parent repository

## License

This Terraform configuration is part of PySOAR. See LICENSE file in repository root.
