# status-pysoar.ps1
# Shows the status and health of all PySOAR containers.

$ProjectDir = $PSScriptRoot
Set-Location $ProjectDir

Write-Host "`n=== PySOAR Container Status ===" -ForegroundColor Cyan
docker-compose ps

Write-Host "`n=== Docker Health Checks ===" -ForegroundColor Cyan
docker ps --filter "name=pysoar" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"

Write-Host "`n=== API Health ===" -ForegroundColor Cyan
try {
    $response = Invoke-WebRequest -Uri "http://localhost:8000/api/v1/health" -TimeoutSec 5 -UseBasicParsing
    Write-Host "API: OK ($($response.StatusCode))" -ForegroundColor Green
} catch {
    Write-Host "API: UNREACHABLE - $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n=== Frontend ===" -ForegroundColor Cyan
try {
    $response = Invoke-WebRequest -Uri "http://localhost" -TimeoutSec 5 -UseBasicParsing
    Write-Host "Frontend: OK ($($response.StatusCode))" -ForegroundColor Green
} catch {
    Write-Host "Frontend: UNREACHABLE - $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host ""
