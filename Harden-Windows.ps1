# Harden-Windows.ps1
# Author: <YOUR NAME>
# AI assistance: Claude (Anthropic) helped draft the 13 control checks.
#   I tested every control on my Windows 11 VM and can explain each line.
# IS2083 Advanced Scripting - Lab 2: Windows Hardening Tool
#
# BEFORE YOU START
#   Save this file as  Harden-Windows.ps1  (remove "_STARTER" from the name).
#   Every command in the lab handout runs  .\Harden-Windows.ps1 , so the name
#   must match exactly.
#
# HOW THIS FILE MATCHES THE LAB HANDOUT
#   Handout Part A, Step 5 ......... run this file once as it is.
#   Handout Part B ................. build the controls in THIS file. Part B has
#                                    two tables:
#                                      "Microsoft Security Baseline controls"
#                                      "Advanced controls (beyond the baseline)"
#                                    Each TODO below names the table and the row
#                                    (the Control column) to use.
#   Handout Part C, Step 6 ......... run an audit.
#   Handout Part D, Step 7 ......... run  .\Harden-Windows.ps1 -Mode Apply
#   The TODOs are numbered 1 to 13 in this file only. Search for "TODO" to
#   find every control you still need to build.
#
# WHAT THIS FILE ALREADY DOES FOR YOU
#   - Two modes: Audit (read only, the default) and Apply (fixes what it safely can).
#   - A weighted security score with a STRONG / MODERATE / NEEDS WORK rating.
#   - A grouped report (Microsoft Security Baseline, then Advanced hardening),
#     saved as a timestamped .txt file in  C:\Users\<you>\<ToolName>_reports
#   - Start and completion pop-ups that show your tool name and score.
#   - Two finished controls you can copy: SMBv1 disabled and SMB server
#     signing required.
#
# HOW TO READ ONE CONTROL (a New-Check)
#   Every control has the same four parts, in this order:
#
#     New-Check $BASELINE 'Control name' {     # 1. category and name
#         ...read the setting...               # 2. TEST block: the first { }
#         @{ Pass = ...; Detail = ... }        #    returns Pass ($true or $false)
#     } {                                      #    and a Detail message
#         ...fix the setting...                # 3. REMEDIATE block: the second { }
#     } 10                                     # 4. weight (points toward the score)
#
#   In the TODO controls, the REMEDIATE block has not been written yet, so the
#   placeholder $null sits in its place. Look for this line:
#
#     } $null 10
#
#   The } closes the TEST block, $null is the empty REMEDIATE slot, and 10 is
#   the weight.
#
# HOW TO BUILD A TODO CONTROL
#   Here is what the finished SMB signing control below looked like as a TODO,
#   and what it looks like finished. Every TODO works the same way.
#
#   BEFORE (a TODO stub):
#     New-Check $BASELINE 'SMB server signing required' {
#         @{ Pass = $false; Detail = 'TODO: ...' }
#     } $null 10
#
#   AFTER (TEST block replaced, and $null swapped for a REMEDIATE block):
#     New-Check $BASELINE 'SMB server signing required' {
#         $c = Get-SmbServerConfiguration -ErrorAction Stop
#         @{ Pass = [bool]$c.RequireSecuritySignature; Detail = "RequireSecuritySignature=$($c.RequireSecuritySignature)" }
#     } {
#         Set-SmbServerConfiguration -RequireSecuritySignature $true -Force
#     } 10
#
#   The TEST block uses the "Audit (read this)" column of the handout table.
#   The REMEDIATE block uses the "Fix (apply this)" column.
#   For the audit only control (BitLocker), keep $null.
#
#   After each control: save, run  .\Harden-Windows.ps1 , and confirm that
#   control now shows its real state.
#
# RUN IT
#   .\Harden-Windows.ps1                # audit only, changes nothing
#   .\Harden-Windows.ps1 -Mode Apply    # audit, fix, re-audit (practice VM only)

param(
    [ValidateSet('Audit','Apply')]
    [string]$Mode = 'Audit'
)

# ======================= SET YOUR TOOL NAME HERE =======================
$ToolName = 'WinGuard'
# =======================================================================

# Category labels used in the code and the report.
$BASELINE = 'Microsoft Security Baseline'
$ADVANCED = 'Advanced hardening'

# The list every New-Check call registers into.
$script:Checks = @()

# ---------- Helper: are we running as Administrator? (done for you) ----------
function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# ---------- Helper: show a pop-up, fall back to the console (done for you) ----------
function Show-Popup {
    param([string]$Message, [string]$Title)
    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        [void][System.Windows.Forms.MessageBox]::Show($Message, $Title)
    } catch {
        Write-Host ('[' + $Title + '] ' + $Message) -ForegroundColor Magenta
    }
}

# ---------- Helper: rate a score (done for you) ----------
function Get-Rating {
    param([int]$Score)
    if ($Score -ge 85)      { return 'STRONG' }
    elseif ($Score -ge 60)  { return 'MODERATE' }
    else                    { return 'NEEDS WORK' }
}

# ---------- Register one control (done for you) ----------
# Usage:  New-Check <Category> '<Name>' { Test returns @{Pass=..;Detail=..} } { Remediate } <Weight>
# Pass $null for the Remediate block to make a control audit only.
function New-Check {
    param(
        [string]$Category,
        [string]$Name,
        [scriptblock]$Test,
        [scriptblock]$Remediate,
        [int]$Weight = 10
    )
    $script:Checks += [pscustomobject]@{
        Category  = $Category
        Name      = $Name
        Test      = $Test
        Remediate = $Remediate
        Weight    = $Weight
    }
}

# =======================================================================
#  Microsoft Security Baseline controls  (category: $BASELINE)
# =======================================================================

# SMBv1 disabled  (DONE: finished example, copy this shape)
New-Check $BASELINE 'SMBv1 disabled' {                 # TEST block starts here
    $c = Get-SmbServerConfiguration -ErrorAction Stop
    @{ Pass = [bool](-not $c.EnableSMB1Protocol); Detail = "EnableSMB1Protocol=$($c.EnableSMB1Protocol)" }
} {                                                    # TEST ends, REMEDIATE starts
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
} 10                                                   # REMEDIATE ends, weight 10

# SMB server signing required  (DONE: the worked example in handout Part B)
New-Check $BASELINE 'SMB server signing required' {
    $c = Get-SmbServerConfiguration -ErrorAction Stop
    @{ Pass = [bool]$c.RequireSecuritySignature; Detail = "RequireSecuritySignature=$($c.RequireSecuritySignature)" }
} {
    Set-SmbServerConfiguration -RequireSecuritySignature $true -Force
} 10

# Control 1: NTLM hardened (refuse LM and NTLMv1)
#   Reads LmCompatibilityLevel from the registry. 5 = send NTLMv2 only, refuse LM and NTLM.
#   -ErrorAction SilentlyContinue: on a new VM the value may not exist, so it reports FAIL, not an error.
New-Check $BASELINE 'NTLM hardened (LmCompatibilityLevel = 5)' {
    $v = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name LmCompatibilityLevel -ErrorAction SilentlyContinue).LmCompatibilityLevel
    $shown = if ($null -eq $v) { 'not set' } else { $v }
    @{ Pass = ($v -eq 5); Detail = "LmCompatibilityLevel=$shown" }
} {
    Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name LmCompatibilityLevel -Value 5 -Type DWord
} 10

# Control 2: User Account Control (UAC) enabled
#   EnableLUA = 1 means UAC is on.
New-Check $BASELINE 'User Account Control (UAC) enabled' {
    $v = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -ErrorAction SilentlyContinue).EnableLUA
    $shown = if ($null -eq $v) { 'not set' } else { $v }
    @{ Pass = ($v -eq 1); Detail = "EnableLUA=$shown" }
} {
    Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -Value 1 -Type DWord
} 10

# Control 3: Minimum password length 14 or more
#   (net accounts) gives lines of text. Find the 'Minimum password length' line
#   and take the number at the end of it.
New-Check $BASELINE 'Minimum password length 14 or more' {
    $line = (net accounts) | Where-Object { $_ -match 'Minimum password length' } | Select-Object -First 1
    $n = 0
    if ($line -match '(\d+)\s*$') { $n = [int]$Matches[1] }
    @{ Pass = ($n -ge 14); Detail = "MinimumPasswordLength=$n" }
} {
    net accounts /minpwlen:14 | Out-Null
} 10

# Control 4: Account lockout threshold 1 to 10
#   'Never' has no number, so it counts as 0 and fails.
New-Check $BASELINE 'Account lockout threshold 1 to 10' {
    $line = (net accounts) | Where-Object { $_ -match 'Lockout threshold' } | Select-Object -First 1
    $n = 0
    if ($line -match '(\d+)\s*$') { $n = [int]$Matches[1] }
    $shown = if ($n -eq 0) { 'Never (0)' } else { $n }
    @{ Pass = ($n -ge 1 -and $n -le 10); Detail = "LockoutThreshold=$shown" }
} {
    net accounts /lockoutthreshold:10 | Out-Null
} 10

# Control 5: Windows Firewall on for every profile (Domain, Private, Public)
New-Check $BASELINE 'Firewall enabled on all profiles' {
    $profiles = Get-NetFirewallProfile -ErrorAction Stop
    $off = @($profiles | Where-Object { "$($_.Enabled)" -ne 'True' })
    $detail = ($profiles | ForEach-Object { "$($_.Name)=$($_.Enabled)" }) -join ', '
    @{ Pass = ($off.Count -eq 0); Detail = $detail }
} {
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
} 10

# Control 6: Microsoft Defender real-time protection on
#   DisableRealtimeMonitoring = $false means real-time protection is ON.
New-Check $BASELINE 'Defender real-time protection on' {
    $m = Get-MpPreference -ErrorAction Stop
    @{ Pass = ($m.DisableRealtimeMonitoring -eq $false); Detail = "DisableRealtimeMonitoring=$($m.DisableRealtimeMonitoring)" }
} {
    Set-MpPreference -DisableRealtimeMonitoring $false
} 10

# Control 7: Guest account disabled
New-Check $BASELINE 'Guest account disabled' {
    $g = Get-LocalUser -Name Guest -ErrorAction Stop
    @{ Pass = (-not $g.Enabled); Detail = "Guest Enabled=$($g.Enabled)" }
} {
    Disable-LocalUser -Name Guest
} 10

# Control 8: RDP requires Network Level Authentication
#   UserAuthentication = 1 means users must sign in before a remote desktop session starts.
New-Check $BASELINE 'RDP requires Network Level Authentication' {
    $v = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -ErrorAction SilentlyContinue).UserAuthentication
    $shown = if ($null -eq $v) { 'not set' } else { $v }
    @{ Pass = ($v -eq 1); Detail = "UserAuthentication=$shown" }
} {
    Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -Value 1 -Type DWord
} 10

# =======================================================================
#  Advanced controls (beyond the baseline)  (category: $ADVANCED)
# =======================================================================

# Control 9: Defender PUA (potentially unwanted application) protection
#   PUAProtection 1 = Enabled (block), 2 = Audit only, 0 = Off.
New-Check $ADVANCED 'Defender PUA protection on' {
    $m = Get-MpPreference -ErrorAction Stop
    @{ Pass = ($m.PUAProtection -eq 1); Detail = "PUAProtection=$($m.PUAProtection)" }
} {
    Set-MpPreference -PUAProtection 1
} 8

# Control 10: ASR rule - block all Office applications from creating child processes
#   Get-MpPreference has two matching lists: rule IDs and their actions.
#   Find where our rule ID sits in the first list, then read the same spot in the second.
#   Action 1 = Block (on), 2 = Audit, 0 = Off.
New-Check $ADVANCED 'ASR: block Office child processes' {
    $ruleId = 'D4F940AB-401B-4EFC-AADC-AD5F3C50688A'
    $m = Get-MpPreference -ErrorAction Stop
    $ids  = @($m.AttackSurfaceReductionRules_Ids)
    $acts = @($m.AttackSurfaceReductionRules_Actions)
    $action = $null
    for ($i = 0; $i -lt $ids.Count; $i++) {
        if ($ids[$i] -eq $ruleId) { $action = $acts[$i] }
    }
    $shown = if ($null -eq $action) { 'rule not configured' } else { "action=$action" }
    @{ Pass = ($action -eq 1); Detail = "ASR $ruleId $shown" }
} {
    Add-MpPreference -AttackSurfaceReductionRules_Ids D4F940AB-401B-4EFC-AADC-AD5F3C50688A -AttackSurfaceReductionRules_Actions Enabled
} 8

# Control 11: PowerShell script block logging
#   Records the PowerShell code that runs, so attacks can be investigated later.
New-Check $ADVANCED 'PowerShell script block logging on' {
    $key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
    $v = (Get-ItemProperty $key -Name EnableScriptBlockLogging -ErrorAction SilentlyContinue).EnableScriptBlockLogging
    $shown = if ($null -eq $v) { 'not set' } else { $v }
    @{ Pass = ($v -eq 1); Detail = "EnableScriptBlockLogging=$shown" }
} {
    $key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
    if (-not (Test-Path $key)) { New-Item -Path $key -Force | Out-Null }
    Set-ItemProperty $key -Name EnableScriptBlockLogging -Value 1 -Type DWord
} 8

# Control 12: LSA protection (RunAsPPL)
#   Protects the LSASS process (which holds passwords in memory) from credential theft tools.
#   Needs a reboot to take effect.
New-Check $ADVANCED 'LSA protection (RunAsPPL) on' {
    $v = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RunAsPPL -ErrorAction SilentlyContinue).RunAsPPL
    $shown = if ($null -eq $v) { 'not set' } else { $v }
    @{ Pass = ($v -eq 1); Detail = "RunAsPPL=$shown" }
} {
    Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RunAsPPL -Value 1 -Type DWord
} 8

# Control 13: BitLocker on the system drive  (AUDIT ONLY: no Remediate block, so $null stays)
#   Turn it on yourself with:  manage-bde -on $env:SystemDrive
#   If BitLocker is not available in the VM, report FAIL with a note instead of an error.
New-Check $ADVANCED 'BitLocker on system drive' {
    try {
        $b = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
        @{ Pass = ("$($b.ProtectionStatus)" -eq 'On'); Detail = "ProtectionStatus=$($b.ProtectionStatus) (audit only)" }
    } catch {
        @{ Pass = $false; Detail = 'BitLocker not available on this system (audit only)' }
    }
} $null 6

# =======================================================================
#  Engine (done for you): audit, apply, report
# =======================================================================

# Run every check, print a grouped report, compute the weighted score.
function Invoke-Audit {
    param([string]$Label = '')

    $results = @()
    foreach ($c in $script:Checks) {
        try {
            $r = & $c.Test
        } catch {
            $r = @{ Pass = $false; Detail = ('error: ' + $_.Exception.Message) }
        }
        $results += [pscustomobject]@{
            Category = $c.Category
            Name     = $c.Name
            Pass     = [bool]$r.Pass
            Detail   = [string]$r.Detail
            Weight   = [int]$c.Weight
        }
    }

    $total  = ($script:Checks | Measure-Object -Property Weight -Sum).Sum
    $earned = (@($results | Where-Object { $_.Pass }) | Measure-Object -Property Weight -Sum).Sum
    if (-not $total)  { $total  = 1 }
    if (-not $earned) { $earned = 0 }
    $score  = [math]::Round(($earned / $total) * 100)
    $rating = Get-Rating -Score $score

    $header = '=== Windows Security Audit ==='
    if ($Label) { $header = $header + '  [' + $Label + ']' }
    Write-Host ''
    Write-Host $header -ForegroundColor Cyan

    foreach ($cat in @($BASELINE, $ADVANCED)) {
        $catResults = @($results | Where-Object { $_.Category -eq $cat })
        if ($catResults.Count -eq 0) { continue }
        $catPass = @($catResults | Where-Object { $_.Pass }).Count
        Write-Host ''
        Write-Host ('-- ' + $cat + '  (' + $catPass + ' of ' + $catResults.Count + ' passing) --') -ForegroundColor White
        foreach ($x in $catResults) {
            if ($x.Pass) {
                Write-Host ('  [PASS] ' + $x.Name) -ForegroundColor Green
            } else {
                Write-Host ('  [FAIL] ' + $x.Name + '  ->  ' + $x.Detail) -ForegroundColor Red
            }
        }
    }

    Write-Host ''
    Write-Host ('Security score: ' + $score + ' / 100   (' + $rating + ')') -ForegroundColor Yellow
    Write-Host ''

    return [pscustomobject]@{
        Label   = $Label
        Results = $results
        Earned  = $earned
        Total   = $total
        Score   = $score
        Rating  = $rating
    }
}

# Make a restore point, then remediate every failing control that has a fix.
function Invoke-Apply {
    $actions = @()

    try {
        Enable-ComputerRestore -Drive 'C:\' -ErrorAction SilentlyContinue
        Checkpoint-Computer -Description ('Before ' + $ToolName + ' hardening') -RestorePointType MODIFY_SETTINGS -ErrorAction Stop
        $actions += 'Created a System Restore Point (your undo button).'
    } catch {
        $actions += 'Could not create a restore point (it may be off or rate limited). Continuing.'
    }

    foreach ($c in $script:Checks) {
        if ($null -eq $c.Remediate) { continue }        # audit-only control
        try { $r = & $c.Test } catch { $r = @{ Pass = $false } }
        if ([bool]$r.Pass) { continue }                 # already passing
        try {
            & $c.Remediate
            $note = 'Remediated: ' + $c.Name
            if ($c.Name -match 'UAC' -or $c.Name -match 'LSA') {
                $note = $note + '   (reboot required to take effect)'
            }
            $actions += $note
        } catch {
            $actions += ('Remediation failed: ' + $c.Name + '  ->  ' + $_.Exception.Message)
        }
    }

    return $actions
}

# Write a timestamped, grouped report and return its path.
function Write-Report {
    param([array]$Summaries, [array]$Actions)

    $dir = Join-Path $env:USERPROFILE ($ToolName + '_reports')
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $path  = Join-Path $dir ($ToolName + '_report_' + $stamp + '.txt')

    $lines = @()
    $lines += ($ToolName + ' Security Report')
    $lines += ('Generated: ' + (Get-Date))
    $lines += ('Computer:  ' + $env:COMPUTERNAME)
    $lines += ''

    foreach ($s in $Summaries) {
        $title = 'AUDIT'
        if ($s.Label) { $title = $s.Label }
        $lines += ('===== ' + $title + ' =====')
        foreach ($cat in @($BASELINE, $ADVANCED)) {
            $cr = @($s.Results | Where-Object { $_.Category -eq $cat })
            if ($cr.Count -eq 0) { continue }
            $cp = @($cr | Where-Object { $_.Pass }).Count
            $lines += ''
            $lines += ('-- ' + $cat + '  (' + $cp + ' of ' + $cr.Count + ' passing) --')
            foreach ($x in $cr) {
                $flag = '[FAIL]'
                if ($x.Pass) { $flag = '[PASS]' }
                $lines += ('  ' + $flag + ' ' + $x.Name + '  ->  ' + $x.Detail)
            }
        }
        $lines += ''
        $lines += ('Security score: ' + $s.Score + ' / 100  (' + $s.Rating + ')')
        $lines += ''
    }

    if ($Actions -and $Actions.Count -gt 0) {
        $lines += '===== Applying hardening ====='
        foreach ($a in $Actions) { $lines += ('  ' + $a) }
        $lines += ''
    }

    $lines | Out-File -FilePath $path -Encoding UTF8
    return $path
}

# =======================================================================
#  Main (done for you)
# =======================================================================

Write-Host ($ToolName + ' Windows Hardening Toolkit') -ForegroundColor Cyan
Show-Popup ($ToolName + ' is starting a security ' + $Mode + '.') ($ToolName + ' starting')

$elevated = Test-Admin
if (-not $elevated) {
    Write-Host 'Note: you are NOT running as Administrator.' -ForegroundColor Yellow
    Write-Host 'Audit will run, but some checks and all fixes need Administrator.' -ForegroundColor Yellow
}

if ($Mode -eq 'Apply') {
    if (-not $elevated) {
        Write-Host 'Apply mode needs Administrator. Re-open PowerShell as administrator and run again with -Mode Apply.' -ForegroundColor Red
        Show-Popup 'Apply mode needs Administrator. Re-run in an elevated PowerShell.' ($ToolName + ' stopped')
        return
    }

    $before = Invoke-Audit -Label 'BEFORE'

    Write-Host '=== Applying safe hardening fixes ===' -ForegroundColor Cyan
    $actions = Invoke-Apply
    foreach ($a in $actions) { Write-Host ('  ' + $a) -ForegroundColor Green }

    $after = Invoke-Audit -Label 'AFTER'

    $report = Write-Report -Summaries @($before, $after) -Actions $actions
    Write-Host ('Report written: ' + $report) -ForegroundColor Cyan

    Show-Popup ($ToolName + ' apply complete.  Before ' + $before.Score + ' / 100,  After ' + $after.Score + ' / 100  (' + $after.Rating + ')') ($ToolName + ' complete')
}
else {
    $audit = Invoke-Audit

    $report = Write-Report -Summaries @($audit) -Actions @()
    Write-Host ('Report written: ' + $report) -ForegroundColor Cyan

    Show-Popup ($ToolName + ' audit complete.  Score ' + $audit.Score + ' / 100  (' + $audit.Rating + ')') ($ToolName + ' complete')
}
