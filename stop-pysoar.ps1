# stop-pysoar.ps1
# Gracefully stops all PySOAR containers.

$ProjectDir = $PSScriptRoot
Set-Location $ProjectDir

Write-Host "Stopping PySOAR containers..."
docker-compose down

if ($LASTEXITCODE -eq 0) {
    Write-Host "PySOAR stopped."
} else {
    Write-Host "ERROR: docker-compose down failed."
    exit 1
}
