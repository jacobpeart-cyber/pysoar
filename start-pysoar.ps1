# start-pysoar.ps1
# Starts Docker Desktop (if not running) and brings up all PySOAR containers.

$ProjectDir = $PSScriptRoot
$LogFile = Join-Path $ProjectDir "pysoar-start.log"

function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$timestamp] $Message"
    Write-Host $line
    Add-Content -Path $LogFile -Value $line
}

Write-Log "=== PySOAR startup initiated ==="

# --- Start Docker Desktop if not running ---
$dockerRunning = $false
try {
    docker info 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) { $dockerRunning = $true }
} catch {}

if (-not $dockerRunning) {
    Write-Log "Docker engine not running. Starting Docker Desktop..."
    $dockerDesktop = "C:\Program Files\Docker\Docker\Docker Desktop.exe"
    if (Test-Path $dockerDesktop) {
        Start-Process $dockerDesktop
    } else {
        Write-Log "ERROR: Docker Desktop not found at expected path. Please start it manually."
        exit 1
    }

    # Wait up to 120 seconds for Docker engine to become ready
    $waited = 0
    while ($waited -lt 120) {
        Start-Sleep -Seconds 5
        $waited += 5
        try {
            docker info 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0) {
                Write-Log "Docker engine is ready (waited ${waited}s)."
                $dockerRunning = $true
                break
            }
        } catch {}
        Write-Log "Waiting for Docker... (${waited}s elapsed)"
    }

    if (-not $dockerRunning) {
        Write-Log "ERROR: Docker engine did not start within 120 seconds. Aborting."
        exit 1
    }
}

# --- Start PySOAR containers ---
Write-Log "Starting PySOAR containers..."
Set-Location $ProjectDir

$output = docker-compose up -d 2>&1
$output | ForEach-Object { Write-Log $_ }

if ($LASTEXITCODE -eq 0) {
    Write-Log "PySOAR is up. Access it at http://localhost"
} else {
    Write-Log "ERROR: docker-compose up failed. Check the log above."
    exit 1
}
