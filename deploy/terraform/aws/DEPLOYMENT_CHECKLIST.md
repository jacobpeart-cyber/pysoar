# AWS Terraform Deployment Checklist

## Pre-Deployment

- [ ] AWS Account created and accessible
- [ ] AWS CLI configured with appropriate credentials
- [ ] Terraform >= 1.0 installed
- [ ] kubectl installed
- [ ] Helm 3+ installed (optional, for application deployment)
- [ ] SSH key pair created in target AWS region
- [ ] Domain name registered (if using custom domain)
- [ ] Budget alerts configured in AWS Console

## Configuration

- [ ] Copy `terraform.tfvars.example` to `terraform.tfvars`
- [ ] Update `terraform.tfvars` with your values:
  - [ ] `aws_region` matches your preferred region
  - [ ] `availability_zones` exist in your region
  - [ ] `eks_cluster_version` matches your requirements
  - [ ] Database credentials set (or use generated)
  - [ ] S3 bucket names are globally unique
  - [ ] VPC CIDR doesn't conflict with existing networks
  - [ ] Custom tags defined
- [ ] Review variable defaults in `variables.tf`
- [ ] Verify no secrets committed to git

## Infrastructure Deployment

- [ ] Run `terraform init` to initialize working directory
- [ ] Run `terraform plan -out=tfplan` and review all changes
- [ ] Verify plan includes:
  - [ ] 1 VPC with 3 public and 3 private subnets
  - [ ] 1 EKS cluster with managed node group
  - [ ] 1 RDS PostgreSQL instance (Multi-AZ if enabled)
  - [ ] 1 ElastiCache Redis replication group
  - [ ] 2 S3 buckets (logs and backups)
  - [ ] KMS keys for encryption
  - [ ] Security groups and IAM roles
  - [ ] CloudWatch resources
  - [ ] WAF Web ACL (if enabled)
- [ ] Run `terraform apply tfplan`
- [ ] Wait for completion (~30-45 minutes)

## Post-Deployment Verification

### EKS Cluster
- [ ] Configure kubectl: `aws eks update-kubeconfig --region <region> --name <cluster-name>`
- [ ] Verify cluster: `kubectl cluster-info`
- [ ] Check nodes: `kubectl get nodes`
- [ ] Verify node status: All nodes should be `Ready`
- [ ] Check system pods: `kubectl get pods -n kube-system`
- [ ] Verify add-ons installed:
  - [ ] vpc-cni
  - [ ] coredns
  - [ ] kube-proxy
  - [ ] aws-ebs-csi-driver

### RDS Database
- [ ] Retrieve endpoint from Terraform outputs
- [ ] Test connection from EKS node:
  ```bash
  kubectl run -it --rm debug --image=postgres:16 --restart=Never -- \
    psql -h <rds-endpoint> -U <username> -d <database>
  ```
- [ ] Verify Multi-AZ enabled: Check AWS Console
- [ ] Confirm backups enabled: Verify 7-day retention
- [ ] Check Performance Insights: Enabled in AWS Console
- [ ] Verify encryption: KMS key in use

### ElastiCache Redis
- [ ] Retrieve endpoint from Terraform outputs
- [ ] Test connection from EKS node:
  ```bash
  kubectl run -it --rm debug --image=redis:7 --restart=Never -- \
    redis-cli -h <redis-endpoint> -p 6379 --tls ping
  ```
- [ ] Verify replication: Primary/replica status in Console
- [ ] Check automatic failover: Enabled
- [ ] Confirm encryption: At-rest and in-transit enabled
- [ ] Verify logs: Check CloudWatch log groups

### S3 Buckets
- [ ] Verify both buckets created (logs, backups)
- [ ] Check public access blocked
- [ ] Confirm versioning enabled
- [ ] Verify encryption:
  - [ ] Logs bucket: AES256
  - [ ] Backups bucket: KMS
- [ ] Check lifecycle policies applied
- [ ] Confirm bucket policies restrict access

### Security
- [ ] Verify KMS key created and rotated
- [ ] Check Secrets Manager secrets created:
  - [ ] Database credentials
  - [ ] Redis auth token
  - [ ] JWT secret key
- [ ] Confirm WAF Web ACL attached (if enabled)
- [ ] Verify security group rules:
  - [ ] RDS allows 5432 from EKS nodes only
  - [ ] Redis allows 6379 from EKS nodes only
  - [ ] EKS allows necessary ingress/egress

### Monitoring & Logging
- [ ] Verify CloudWatch log groups created:
  - [ ] EKS cluster logs
  - [ ] Application logs
  - [ ] SIEM logs
  - [ ] Redis slow-log
  - [ ] Redis engine-log
  - [ ] VPC Flow Logs
- [ ] Check CloudWatch alarms (if monitoring enabled):
  - [ ] RDS CPU > 80%
  - [ ] RDS storage < 5GB
  - [ ] Redis CPU > 75%
  - [ ] Redis memory > 80%
  - [ ] EKS node count
- [ ] Verify dashboard created
- [ ] Test SNS topic subscription for alerts

### IAM & Access
- [ ] Verify OIDC provider created for IRSA
- [ ] Confirm IAM roles for service accounts:
  - [ ] VPC CNI role
  - [ ] EBS CSI driver role
  - [ ] Application secrets access role
- [ ] Test pod-level secrets access:
  ```bash
  kubectl create serviceaccount pysoar-app
  kubectl create rolebinding pysoar-app-role \
    --clusterrole=edit \
    --serviceaccount=default:pysoar-app
  # Verify service account IRSA annotation
  ```

## Application Deployment

- [ ] Prepare Docker images for PySOAR
- [ ] Create Kubernetes manifests/Helm charts
- [ ] Deploy application to EKS cluster
- [ ] Verify pods are running: `kubectl get pods`
- [ ] Check pod logs: `kubectl logs <pod-name>`
- [ ] Test application endpoints
- [ ] Verify database connectivity from application
- [ ] Verify Redis connectivity from application
- [ ] Test secret retrieval from application pods

## Operational Handoff

- [ ] Document deployed infrastructure
- [ ] Save Terraform state securely (S3 backend recommended)
- [ ] Configure Terraform remote state (if not using local)
- [ ] Create operations runbook
- [ ] Document emergency procedures
- [ ] Set up backup schedules
- [ ] Configure monitoring alerts recipients
- [ ] Train operations team on infrastructure
- [ ] Document scaling procedures
- [ ] Create disaster recovery plan

## Cost Optimization Review

- [ ] Review estimated monthly costs
- [ ] Validate reserved capacity planning
- [ ] Check for unused resources
- [ ] Confirm instance types are appropriate
- [ ] Review storage allocation
- [ ] Validate backup retention periods
- [ ] Check CloudWatch log retention
- [ ] Review WAF costs (if enabled)

## Security Review

- [ ] Run AWS Config checks
- [ ] Review IAM policies for least privilege
- [ ] Verify all data encryption keys are in use
- [ ] Confirm deletion protection enabled on critical resources
- [ ] Review security group rules for unnecessarily open ports
- [ ] Validate VPC Flow Logs are being collected
- [ ] Confirm MFA enabled for AWS Console access
- [ ] Review and document any exceptions to security policies

## Decommissioning (if needed later)

- [ ] Backup all critical data from RDS and Redis
- [ ] Export data from S3
- [ ] Drain all pods from EKS cluster
- [ ] Create final RDS snapshot
- [ ] Run `terraform destroy` to remove all infrastructure
- [ ] Verify all resources deleted in AWS Console
- [ ] Cancel any associated AWS services

---

**Deployment Date**: ________________
**Deployed By**: ________________
**Reviewed By**: ________________
**Notes**: 
```




