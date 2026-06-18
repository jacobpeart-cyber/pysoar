<#
.SYNOPSIS
  Install/upgrade the PySOAR log-forwarder scheduled task to run as SYSTEM.

.DESCRIPTION
  Must run ELEVATED. Registers PySOAR-LogForwarder to run as the SYSTEM
  account with highest privileges, every 5 minutes. SYSTEM can read the
  Windows Security log (logons, failed auth, privilege changes) — which a
  normal user task cannot — so this is what unlocks full SOC coverage.

  Run it via the self-elevating one-liner (see README), or from an
  elevated PowerShell:  pwsh -File install-forwarder-task.ps1
#>

$ErrorActionPreference = "Stop"

# Refuse to run unelevated — the whole point is the SYSTEM principal.
$elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
            ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $elevated) {
  Write-Error "This script must be run elevated (as Administrator). See the self-elevating one-liner."
  exit 1
}

$pwsh = (Get-Command pwsh).Source
$script = Join-Path $PSScriptRoot "pysoar-log-forwarder.ps1"
if (-not (Test-Path $script)) { Write-Error "Forwarder not found at $script"; exit 1 }

$action = New-ScheduledTaskAction -Execute $pwsh `
  -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$script`""
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 5)
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
  -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 4)
# SYSTEM service account: always present, no stored password, can read Security log.
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

Register-ScheduledTask -TaskName "PySOAR-LogForwarder" -Action $action -Trigger $trigger `
  -Settings $settings -Principal $principal `
  -Description "Forwards Windows Event Logs (incl. Security) to PySOAR SIEM every 5 min" -Force | Out-Null

# Make sure SYSTEM can read the config + write the state watermarks.
$base = "C:\ProgramData\PySOAR"
icacls $base /grant "SYSTEM:(OI)(CI)F" | Out-Null

Write-Host "Task installed as SYSTEM. Running it once now..." -ForegroundColor Green
Start-ScheduledTask -TaskName "PySOAR-LogForwarder"
Start-Sleep 8
$info = Get-ScheduledTaskInfo -TaskName "PySOAR-LogForwarder"
Write-Host "LastRunTime: $($info.LastRunTime)  LastResult: $($info.LastTaskResult) (0 = success)"
Write-Host "Done. Security + System + Application logs now forward every 5 minutes." -ForegroundColor Green
