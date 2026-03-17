# PySOAR Module Outputs

output "public_ip" {
  description = "Elastic IP address of the PySOAR instance"
  value       = aws_eip.pysoar.public_ip
}

output "instance_id" {
  description = "EC2 instance ID"
  value       = aws_instance.pysoar.id
}

output "security_group_id" {
  description = "Security group ID"
  value       = aws_security_group.pysoar.id
}

output "pysoar_url" {
  description = "URL to access PySOAR"
  value       = "http://${aws_eip.pysoar.public_ip}"
}

output "ssh_command" {
  description = "SSH command to connect to the instance"
  value       = "ssh -i YOUR_KEY.pem ubuntu@${aws_eip.pysoar.public_ip}"
}
