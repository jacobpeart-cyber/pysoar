# setup-autostart.ps1
# Run this ONCE as Administrator to register PySOAR as a Windows startup task.
# It will automatically start Docker Desktop and all PySOAR containers at login.

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "ERROR: This script must be run as Administrator." -ForegroundColor Red
    Write-Host "Right-click setup-autostart.ps1 and choose 'Run as administrator'."
    exit 1
}

$ProjectDir = $PSScriptRoot
$StartScript = Join-Path $ProjectDir "start-pysoar.ps1"
$TaskName = "PySOAR Autostart"

if (-not (Test-Path $StartScript)) {
    Write-Host "ERROR: start-pysoar.ps1 not found at $StartScript" -ForegroundColor Red
    exit 1
}

# Remove existing task if present
$existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($existing) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    Write-Host "Removed existing '$TaskName' task."
}

# Build the task
$action = New-ScheduledTaskAction `
    -Execute "powershell.exe" `
    -Argument "-NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$StartScript`""

# Trigger: at logon for the current user, with a 30-second delay to let the desktop settle
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
$trigger.Delay = "PT30S"   # 30-second delay

$settings = New-ScheduledTaskSettingsSet `
    -ExecutionTimeLimit (New-TimeSpan -Hours 1) `
    -RestartCount 2 `
    -RestartInterval (New-TimeSpan -Minutes 1) `
    -StartWhenAvailable

$principal = New-ScheduledTaskPrincipal `
    -UserId $env:USERNAME `
    -LogonType Interactive `
    -RunLevel Highest

Register-ScheduledTask `
    -TaskName $TaskName `
    -Action $action `
    -Trigger $trigger `
    -Settings $settings `
    -Principal $principal `
    -Description "Starts Docker Desktop and PySOAR containers at Windows login" | Out-Null

Write-Host ""
Write-Host "=== PySOAR Autostart Registered ===" -ForegroundColor Green
Write-Host "Task name : $TaskName"
Write-Host "Triggers  : At login for $env:USERNAME (30s delay)"
Write-Host "Script    : $StartScript"
Write-Host ""
Write-Host "PySOAR will now start automatically every time you log in."
Write-Host "To start it right now without rebooting, run:"
Write-Host "  .\start-pysoar.ps1" -ForegroundColor Cyan
Write-Host ""
Write-Host "To remove autostart later, run:"
Write-Host "  Unregister-ScheduledTask -TaskName '$TaskName' -Confirm:`$false" -ForegroundColor Yellow
