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

# POST as NDJSON. TLS is verified by pinning the server cert thumbprint
# (config.cert_thumbprint) — MITM-safe even with the self-signed cert, so
# the API key + log contents can't be intercepted. Falls back to normal
# CA validation when no thumbprint is set; only skips verification if the
# operator explicitly opts in via insecure_skip_tls_verify (default off).
$body = ($batch -join "`n")
$pinned = ("$($cfg.cert_thumbprint)" -replace '[^0-9A-Fa-f]', '')
$insecure = [bool]$cfg.insecure_skip_tls_verify

# Thumbprint validation is done in a compiled (C#) callback rather than a
# PowerShell scriptblock: .NET invokes the cert callback on a thread with
# no PowerShell runspace, where scriptblock delegates fail. The compiled
# static method runs reliably on any thread.
if (-not ([System.Management.Automation.PSTypeName]'PySoarPinnedTls').Type) {
  $refAsms = @(
    [System.Net.Http.HttpRequestMessage].Assembly.Location,
    [System.Security.Cryptography.X509Certificates.X509Certificate2].Assembly.Location,
    [System.Net.Security.SslPolicyErrors].Assembly.Location,
    [System.Net.Http.HttpClientHandler].Assembly.Location
  ) | Select-Object -Unique
  Add-Type -TypeDefinition @"
using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
public static class PySoarPinnedTls {
    public static string Expected = "";
    public static bool Insecure = false;
    public static bool Validate(HttpRequestMessage m, X509Certificate2 cert, X509Chain chain, SslPolicyErrors errors) {
        if (Insecure) return true;
        if (string.IsNullOrEmpty(Expected)) return errors == SslPolicyErrors.None;
        return cert != null && cert.Thumbprint != null &&
               cert.Thumbprint.Equals(Expected, System.StringComparison.OrdinalIgnoreCase);
    }
}
"@ -ReferencedAssemblies $refAsms
}
[PySoarPinnedTls]::Expected = $pinned
[PySoarPinnedTls]::Insecure = $insecure
if ($insecure) { Write-Warning "TLS verification disabled (insecure_skip_tls_verify=true) — set cert_thumbprint instead." }

$cbType = [System.Func[System.Net.Http.HttpRequestMessage, `
  System.Security.Cryptography.X509Certificates.X509Certificate2, `
  System.Security.Cryptography.X509Certificates.X509Chain, `
  System.Net.Security.SslPolicyErrors, bool]]
$handler = [System.Net.Http.HttpClientHandler]::new()
$handler.ServerCertificateCustomValidationCallback = [System.Delegate]::CreateDelegate($cbType, [PySoarPinnedTls].GetMethod("Validate"))

$client = [System.Net.Http.HttpClient]::new($handler)
$client.Timeout = [TimeSpan]::FromSeconds(60)
$content = [System.Net.Http.StringContent]::new($body, [System.Text.Encoding]::UTF8, "application/x-ndjson")
$client.DefaultRequestHeaders.Add("X-API-Key", $cfg.api_key)
try {
  $resp = $client.PostAsync($ingestUrl, $content).GetAwaiter().GetResult()
  $text = $resp.Content.ReadAsStringAsync().GetAwaiter().GetResult()
  if (-not $resp.IsSuccessStatusCode) {
    Write-Error "ingest POST failed: HTTP $([int]$resp.StatusCode) $text"; exit 1
  }
  $parsed = $text | ConvertFrom-Json
  Write-Output "forwarded $($batch.Count) events -> success=$($parsed.success_count) alerts=$($parsed.alerts_generated)"
} catch {
  Write-Error "ingest POST failed: $($_.Exception.Message)"; exit 1
} finally {
  $content.Dispose(); $client.Dispose(); $handler.Dispose()
}
