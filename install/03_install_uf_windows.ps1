<#
  -------------------------------------------------------------------------
  Installs and configures the Universal Forwarder on a Windows endpoint.

  Installing the agent is the easy half. The audit subcategories and
  PowerShell logging policies set below are what actually make the Windows
  detections possible: without them the rules deploy and enable cleanly but
  can never fire, because the events they match are never written.

  Run elevated:
      Set-ExecutionPolicy -Scope Process Bypass -Force
      .\03_install_uf_windows.ps1 -IndexerHost 10.20.30.10
  -------------------------------------------------------------------------
#>
[CmdletBinding()]
param(
    [string] $IndexerHost  = "10.20.30.10",
    [int]    $S2SPort      = 9997,
    [string] $UfVersion    = "9.4.3",
    [string] $UfBuild      = "b5e4f9b5b2a2",
    [string] $UfHome       = "C:\Program Files\SplunkUniversalForwarder",
    [string] $AdminUser    = "admin",
    [string] $AdminPassword= "ChangeMe_Now!",
    [string] $ConfSource   = (Join-Path (Split-Path $PSScriptRoot -Parent) "forwarders\windows")
)

$ErrorActionPreference = 'Stop'
function Log  ($m) { Write-Host "[+] $m" -ForegroundColor Green }
function Warn ($m) { Write-Host "[!] $m" -ForegroundColor Yellow }

if (-not ([Security.Principal.WindowsPrincipal] `
        [Security.Principal.WindowsIdentity]::GetCurrent()
      ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "This script must be run from an elevated PowerShell session."
}

# --- Install the Universal Forwarder ---------------------------------------
function Install-UF {
    if (Test-Path (Join-Path $UfHome "bin\splunk.exe")) {
        Log "UF already installed at $UfHome"
        return
    }
    $msi = "splunkforwarder-$UfVersion-$UfBuild-windows-x64.msi"
    $url = "https://download.splunk.com/products/universalforwarder/releases/$UfVersion/windows/$msi"
    $dst = Join-Path $env:TEMP $msi

    if (-not (Test-Path $dst)) {
        Log "downloading $msi"
        Invoke-WebRequest -Uri $url -OutFile $dst -UseBasicParsing
    }

    Log "installing silently"
    $args = @(
        "/i", "`"$dst`"",
        "AGREETOLICENSE=Yes",
        "SPLUNKUSERNAME=$AdminUser",
        "SPLUNKPASSWORD=$AdminPassword",
        "RECEIVING_INDEXER=$IndexerHost`:$S2SPort",
        "WINEVENTLOG_SEC_ENABLE=1",
        "WINEVENTLOG_SYS_ENABLE=1",
        "WINEVENTLOG_APP_ENABLE=1",
        "LAUNCHSPLUNK=1",
        "SERVICESTARTTYPE=auto",
        "/quiet", "/norestart"
    )
    Start-Process msiexec.exe -ArgumentList $args -Wait -NoNewWindow
}

# --- Deploy configuration --------------------------------------------------
function Deploy-Confs {
    $local = Join-Path $UfHome "etc\system\local"
    New-Item -ItemType Directory -Force -Path $local | Out-Null

    foreach ($f in @("inputs.conf", "outputs.conf", "deploymentclient.conf")) {
        $src = Join-Path $ConfSource "etc\system\local\$f"
        $dst = Join-Path $local $f
        if (Test-Path $dst -and -not (Test-Path "$dst.orig")) {
            Copy-Item $dst "$dst.orig"
        }
        (Get-Content $src -Raw).
            Replace('__INDEXER_HOST__', $IndexerHost).
            Replace('__S2S_PORT__', "$S2SPort") |
            Set-Content -Path $dst -Encoding ASCII
        Log "  -> $f"
    }

    $binDir = Join-Path $UfHome "bin"
    Copy-Item (Join-Path $ConfSource "bin\windows_host_health.ps1") `
              (Join-Path $binDir "windows_host_health.ps1") -Force
}

# --- Audit policy -----------------------------------------------------------
# Each subcategory maps to the detections that depend on it. Enabling File
# System auditing alone is not sufficient for the ransomware rule - SACLs must
# also be set on the directories you want watched.
function Enable-AuditPolicies {
    Log "enabling advanced audit policies"
    # 4624 / 4625 - logon success and failure (brute-force detection)
    auditpol /set /subcategory:"Logon" /success:enable /failure:enable | Out-Null
    # 4672 - special privileges assigned at logon
    auditpol /set /subcategory:"Special Logon" /success:enable | Out-Null
    # 4728 / 4732 - privileged group membership changes
    auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable | Out-Null
    # 7045 - service installation
    auditpol /set /subcategory:"Security System Extension" /success:enable | Out-Null
    # 4663 - object access (ransomware behaviour heuristic)
    auditpol /set /subcategory:"File System" /success:enable /failure:enable | Out-Null
    # 5140 - file share access (lateral movement)
    auditpol /set /subcategory:"File Share" /success:enable /failure:enable | Out-Null
    # 1102 / 4719 - audit log cleared, audit policy changed
    auditpol /set /subcategory:"Audit Policy Change" /success:enable | Out-Null
    # 4688 with command line - process creation, the fallback where Sysmon
    # is not deployed. Command-line capture is off by default and is what
    # makes 4688 useful rather than merely noisy.
    auditpol /set /subcategory:"Process Creation" /success:enable | Out-Null
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
        /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f | Out-Null
}

function Enable-PowerShellLogging {
    Log "enabling PowerShell script block + module logging"
    $sb = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
    New-Item -Path $sb -Force | Out-Null
    Set-ItemProperty -Path $sb -Name EnableScriptBlockLogging -Value 1 -Type DWord

    $mod = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
    New-Item -Path $mod -Force | Out-Null
    Set-ItemProperty -Path $mod -Name EnableModuleLogging -Value 1 -Type DWord
    New-Item -Path "$mod\ModuleNames" -Force | Out-Null
    Set-ItemProperty -Path "$mod\ModuleNames" -Name "*" -Value "*"

    $tr = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
    New-Item -Path $tr -Force | Out-Null
    Set-ItemProperty -Path $tr -Name EnableTranscripting -Value 1 -Type DWord
}

function Install-Sysmon {
    # Optional. Sysmon gives richer process telemetry (parent process, hashes,
    # command line) than 4688; the detections work without it but with less
    # context.
    if (Get-Service -Name Sysmon64 -ErrorAction SilentlyContinue) {
        Log "Sysmon already installed"
        return
    }
    Warn "Sysmon not installed - process-based detections fall back to EventCode 4688."
    Warn "  Install with: sysmon64.exe -accepteula -i sysmonconfig.xml"
}

# --- Restart and confirm ---------------------------------------------------
function Restart-And-Verify {
    Log "restarting SplunkForwarder service"
    Restart-Service SplunkForwarder -Force
    Start-Sleep -Seconds 10

    $splunk = Join-Path $UfHome "bin\splunk.exe"
    Log "forward-server status:"
    & $splunk list forward-server -auth "$AdminUser`:$AdminPassword"

    Log "confirm on the indexer with:"
    Write-Host "      index=windows host=$env:COMPUTERNAME | stats count by sourcetype"
}

Install-UF
Deploy-Confs
Enable-AuditPolicies
Enable-PowerShellLogging
Install-Sysmon
Restart-And-Verify
Log "Windows Universal Forwarder configured against $IndexerHost`:$S2SPort"
