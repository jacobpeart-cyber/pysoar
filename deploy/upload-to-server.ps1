# upload-to-server.ps1
# Uploads PySOAR code to your Oracle Cloud server via SCP
# Usage: .\upload-to-server.ps1 -ServerIP "1.2.3.4" -KeyFile "C:\path\to\key.pem"

param(
    [Parameter(Mandatory=$true)]
    [string]$ServerIP,

    [Parameter(Mandatory=$true)]
    [string]$KeyFile
)

$ProjectDir = $PSScriptRoot | Split-Path -Parent

Write-Host "Uploading PySOAR to $ServerIP..."
Write-Host ""

# Create /opt/pysoar on the server
ssh -i $KeyFile -o StrictHostKeyChecking=no "ubuntu@$ServerIP" "sudo mkdir -p /opt/pysoar && sudo chown ubuntu:ubuntu /opt/pysoar"

# Upload project files (exclude node_modules, venv, __pycache__, .git, local db)
scp -i $KeyFile -r `
  "$ProjectDir\src" `
  "$ProjectDir\frontend" `
  "$ProjectDir\alembic" `
  "$ProjectDir\nginx" `
  "$ProjectDir\deploy" `
  "$ProjectDir\docker-compose.yml" `
  "$ProjectDir\Dockerfile" `
  "$ProjectDir\requirements.txt" `
  "ubuntu@${ServerIP}:/opt/pysoar/"

Write-Host ""
Write-Host "Upload complete."
Write-Host ""
Write-Host "Now SSH into the server and run:"
Write-Host "  ssh -i $KeyFile ubuntu@$ServerIP"
Write-Host "  bash /opt/pysoar/deploy/server-setup.sh"
