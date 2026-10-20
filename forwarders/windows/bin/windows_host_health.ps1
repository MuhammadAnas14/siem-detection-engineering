# ---------------------------------------------------------------------------
# Scripted input referenced by etc\system\local\inputs.conf.
#
# Windows counterpart to linux_host_health.sh. Runs on every endpoint every
# interval, so it stays deliberately cheap.
#
# Install to: %SPLUNK_HOME%\bin\windows_host_health.ps1
# ---------------------------------------------------------------------------
$ErrorActionPreference = 'SilentlyContinue'

$ts   = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$host_fqdn = [System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName

$os  = Get-CimInstance Win32_OperatingSystem
$cpu = (Get-CimInstance Win32_Processor |
        Measure-Object -Property LoadPercentage -Average).Average
$memUsedPct = [math]::Round(
    (($os.TotalVisibleMemorySize - $os.FreePhysicalMemory) /
      $os.TotalVisibleMemorySize) * 100, 2)
$disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'"
$diskUsedPct = [math]::Round((($disk.Size - $disk.FreeSpace) / $disk.Size) * 100, 2)
$uptimeSecs = [int]((Get-Date) - $os.LastBootUpTime).TotalSeconds

# Self-reported forwarder version for the version inventory.
$ufHome = $env:SPLUNK_HOME
if (-not $ufHome) { $ufHome = "C:\Program Files\SplunkUniversalForwarder" }
$ufVersion = "unknown"
$verFile = Join-Path $ufHome "etc\splunk.version"
if (Test-Path $verFile) {
    $ufVersion = (Select-String -Path $verFile -Pattern '^VERSION=').Line -replace 'VERSION=',''
}

# Failed-logon tally for the interval, as a cheap cross-check that the
# Security log input is actually flowing.
$failed = (Get-WinEvent -FilterHashtable @{
    LogName='Security'; Id=4625; StartTime=(Get-Date).AddMinutes(-5)
} -ErrorAction SilentlyContinue | Measure-Object).Count

$fields = @(
    "host=$host_fqdn"
    "os=windows"
    "cpu_used_pct=$cpu"
    "mem_used_pct=$memUsedPct"
    "disk_used_pct=$diskUsedPct"
    "uptime_secs=$uptimeSecs"
    "uf_version=$ufVersion"
    "failed_logins_5m=$failed"
    "defender_enabled=$((Get-MpComputerStatus).RealTimeProtectionEnabled)"
) -join ' '

Write-Output "$ts $fields"
