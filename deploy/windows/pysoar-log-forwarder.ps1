<#
.SYNOPSIS
  Forward Windows Event Logs to PySOAR's authenticated SIEM ingest API.

.DESCRIPTION
  Reads new security-relevant events from the Windows Event Logs since the
  last run (per-log timestamp watermark) and POSTs them as NDJSON to
  PySOAR's /api/v1/siem/logs/ingest/bulk endpoint over HTTPS, authenticated
  with an API key. Designed to run as a scheduled task (SYSTEM) every few
  minutes. Config + API key live in C:\ProgramData\PySOAR\config.json
  (out of source control); state watermarks in C:\ProgramData\PySOAR\state.

  Reading the Security log requires elevation — run the task as SYSTEM.
#>

$ErrorActionPreference = "Stop"
$Base = "C:\ProgramData\PySOAR"
$StateDir = Join-Path $Base "state"

$cfg = Get-Content (Join-Path $Base "config.json") -Raw | ConvertFrom-Json
$ingestUrl = "$($cfg.server_url)/api/v1/siem/logs/ingest/bulk"
$hostName = $env:COMPUTERNAME

# Curated security-relevant Security-log event IDs (the log is huge; we
# only forward what a SOC cares about). System/Application are filtered by
# severity level instead.
$SecurityIds = @(1102,4624,4625,4634,4648,4672,4688,4720,4722,4723,4724,4725,
                 4726,4728,4732,4740,4756,4768,4769,4776,5140,5145)

function Get-Severity([int]$level) {
  switch ($level) { 1 {"critical"} 2 {"high"} 3 {"medium"} 4 {"low"} default {"informational"} }
}

function Get-Watermark([string]$log) {
  $f = Join-Path $StateDir "$log.watermark"
  if (Test-Path $f) { return [datetime](Get-Content $f -Raw).Trim() }
  return (Get-Date).AddHours(-1)   # first run: last hour only, avoid a flood
}

function Set-Watermark([string]$log, [datetime]$ts) {
  Set-Content -Path (Join-Path $StateDir "$log.watermark") -Value $ts.ToString("o") -Encoding ASCII
}

$batch = New-Object System.Collections.Generic.List[string]
$maxEvents = [int]$cfg.max_events_per_run

foreach ($log in $cfg.logs) {
  $since = Get-Watermark $log
  $filter = @{ LogName = $log; StartTime = $since }
  if ($log -eq "Security") { $filter["Id"] = $SecurityIds } else { $filter["Level"] = @(1,2,3) }

  try {
    $events = Get-WinEvent -FilterHashtable $filter -MaxEvents $maxEvents -ErrorAction Stop |
              Sort-Object TimeCreated
  } catch {
    # "No events found" is a normal, non-fatal condition.
    if ($_.Exception.Message -match "No events were found") { continue }
    Write-Warning "skip ${log}: $($_.Exception.Message)"; continue
  }

  $newest = $since
  foreach ($e in $events) {
    $msg = ($e.Message -replace "\r?\n", " ")
    if ($msg.Length -gt 2000) { $msg = $msg.Substring(0,2000) }
    $obj = [ordered]@{
      raw_log     = "EventID=$($e.Id) $msg"
      message     = $msg
      source_type = "windows_eventlog"
      source_name = "$hostName/$log"
      hostname    = $hostName
      severity    = (Get-Severity $e.Level)
      timestamp   = $e.TimeCreated.ToUniversalTime().ToString("o")
      event_id    = $e.Id
      provider    = $e.ProviderName
    }
    $batch.Add(($obj | ConvertTo-Json -Compress))
    if ($e.TimeCreated -gt $newest) { $newest = $e.TimeCreated }
  }
  Set-Watermark $log $newest
}

if ($batch.Count -eq 0) { Write-Output "no new events"; return }

# POST as NDJSON. PS7 has -SkipCertificateCheck for the self-signed cert.
$body = ($batch -join "`n")
$headers = @{ "X-API-Key" = $cfg.api_key; "Content-Type" = "application/x-ndjson" }
try {
  $resp = Invoke-RestMethod -Uri $ingestUrl -Method Post -Headers $headers -Body $body `
            -SkipCertificateCheck -TimeoutSec 60
  Write-Output "forwarded $($batch.Count) events -> success=$($resp.success_count) alerts=$($resp.alerts_generated)"
} catch {
  Write-Error "ingest POST failed: $($_.Exception.Message)"
  exit 1
}
