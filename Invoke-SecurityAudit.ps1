<#
.SYNOPSIS
    Read-only security baseline audit of a Windows 10/11 workstation.

.DESCRIPTION
    Checks common hardening points (inspired by the CIS Benchmarks and ANSSI
    recommendations) and produces a console summary plus an HTML report.
    Nothing is modified on the machine.

    Some checks need administrator rights; without them they are reported as
    "SKIPPED" instead of failing.

.PARAMETER ReportPath
    HTML report path. Default: .\security-audit-<computer>-<date>.html

.PARAMETER NoHtml
    Console output only.

.EXAMPLE
    .\Invoke-SecurityAudit.ps1

.EXAMPLE
    .\Invoke-SecurityAudit.ps1 -ReportPath C:\Audit\pc01.html
#>
[CmdletBinding()]
param(
    [string]$ReportPath = (Join-Path (Get-Location) ("security-audit-{0}-{1:yyyyMMdd-HHmm}.html" -f $env:COMPUTERNAME, (Get-Date))),
    [switch]$NoHtml
)

Set-StrictMode -Version Latest

$results = New-Object System.Collections.Generic.List[object]

function Add-Result {
    param(
        [string]$Category,
        [string]$Check,
        [ValidateSet('PASS', 'WARN', 'FAIL', 'INFO', 'SKIPPED')][string]$Status,
        [string]$Detail,
        [string]$Recommendation = ''
    )
    $results.Add([pscustomobject]@{
        Category       = $Category
        Check          = $Check
        Status         = $Status
        Detail         = $Detail
        Recommendation = $Recommendation
    })
}

function Get-RegValue {
    param([string]$Path, [string]$Name)
    try { (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name } catch { $null }
}

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)

# --- System -----------------------------------------------------------------
$os = Get-CimInstance Win32_OperatingSystem
Add-Result 'System' 'Operating system' 'INFO' ("{0} build {1}" -f $os.Caption, $os.BuildNumber)

$lastBoot = $os.LastBootUpTime
$uptimeDays = [int]((Get-Date) - $lastBoot).TotalDays
if ($uptimeDays -gt 30) {
    Add-Result 'System' 'Uptime' 'WARN' "$uptimeDays days since last reboot" 'Reboot regularly so that updates are fully applied.'
} else {
    Add-Result 'System' 'Uptime' 'PASS' "$uptimeDays days since last reboot"
}

# --- Updates ----------------------------------------------------------------
try {
    $lastHotfix = Get-HotFix -ErrorAction Stop | Where-Object { $_.InstalledOn } |
        Sort-Object InstalledOn -Descending | Select-Object -First 1
    if ($lastHotfix) {
        $age = [int]((Get-Date) - $lastHotfix.InstalledOn).TotalDays
        $status = if ($age -le 45) { 'PASS' } else { 'FAIL' }
        Add-Result 'Updates' 'Last installed update' $status ("{0} installed {1} days ago" -f $lastHotfix.HotFixID, $age) 'Install the monthly cumulative update.'
    } else {
        Add-Result 'Updates' 'Last installed update' 'WARN' 'No dated update found'
    }
} catch {
    Add-Result 'Updates' 'Last installed update' 'SKIPPED' $_.Exception.Message
}

# --- Firewall ---------------------------------------------------------------
try {
    foreach ($p in Get-NetFirewallProfile -ErrorAction Stop) {
        if ($p.Enabled) {
            Add-Result 'Firewall' "Profile $($p.Name)" 'PASS' 'Enabled'
        } else {
            Add-Result 'Firewall' "Profile $($p.Name)" 'FAIL' 'Disabled' 'Enable Windows Defender Firewall on every profile.'
        }
    }
} catch {
    Add-Result 'Firewall' 'Firewall profiles' 'SKIPPED' $_.Exception.Message
}

# --- Antivirus --------------------------------------------------------------
try {
    $mp = Get-MpComputerStatus -ErrorAction Stop
    Add-Result 'Antivirus' 'Real-time protection' ($(if ($mp.RealTimeProtectionEnabled) { 'PASS' } else { 'FAIL' })) `
        ("RealTimeProtectionEnabled = {0}" -f $mp.RealTimeProtectionEnabled) 'Turn on Microsoft Defender real-time protection.'
    $sigAge = $mp.AntivirusSignatureAge
    Add-Result 'Antivirus' 'Signature age' ($(if ($sigAge -le 3) { 'PASS' } else { 'WARN' })) "$sigAge day(s)" 'Update antivirus signatures.'
} catch {
    Add-Result 'Antivirus' 'Microsoft Defender' 'INFO' 'Defender status unavailable (third-party antivirus?)'
}

# --- Accounts ---------------------------------------------------------------
try {
    $guest = Get-LocalUser -ErrorAction Stop | Where-Object { $_.SID.Value -like '*-501' }
    if ($guest) {
        Add-Result 'Accounts' 'Guest account' ($(if ($guest.Enabled) { 'FAIL' } else { 'PASS' })) `
            ("{0} enabled = {1}" -f $guest.Name, $guest.Enabled) 'Disable the built-in Guest account.'
    }
    $admin = Get-LocalUser | Where-Object { $_.SID.Value -like '*-500' }
    if ($admin) {
        Add-Result 'Accounts' 'Built-in Administrator' ($(if ($admin.Enabled) { 'WARN' } else { 'PASS' })) `
            ("{0} enabled = {1}" -f $admin.Name, $admin.Enabled) 'Keep the built-in Administrator disabled; use named admin accounts (LAPS in a domain).'
    }
    $admins = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop)
    $status = if ($admins.Count -le 2) { 'PASS' } else { 'WARN' }
    Add-Result 'Accounts' 'Local administrators' $status ("{0} member(s): {1}" -f $admins.Count, (($admins | ForEach-Object Name) -join ', ')) 'Limit local admin rights (least privilege).'
} catch {
    Add-Result 'Accounts' 'Local accounts' 'SKIPPED' $_.Exception.Message
}

# --- UAC --------------------------------------------------------------------
$uac = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA'
Add-Result 'Hardening' 'User Account Control' ($(if ($uac -eq 1) { 'PASS' } else { 'FAIL' })) "EnableLUA = $uac" 'Enable UAC.'

# --- Remote Desktop ---------------------------------------------------------
$rdpDenied = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections'
if ($rdpDenied -eq 0) {
    $nla = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication'
    Add-Result 'Remote access' 'Remote Desktop' ($(if ($nla -eq 1) { 'WARN' } else { 'FAIL' })) `
        ("RDP enabled, NLA = {0}" -f $nla) 'Disable RDP if unused; otherwise require NLA and restrict it to a VPN or admin network.'
} else {
    Add-Result 'Remote access' 'Remote Desktop' 'PASS' 'RDP disabled'
}

# --- SMBv1 ------------------------------------------------------------------
try {
    $smb1 = (Get-SmbServerConfiguration -ErrorAction Stop).EnableSMB1Protocol
    Add-Result 'Hardening' 'SMBv1 server' ($(if ($smb1) { 'FAIL' } else { 'PASS' })) "EnableSMB1Protocol = $smb1" 'Disable SMBv1 (WannaCry / EternalBlue).'
} catch {
    Add-Result 'Hardening' 'SMBv1 server' 'SKIPPED' 'Requires administrator rights'
}

# --- AutoRun ----------------------------------------------------------------
$autorun = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun'
Add-Result 'Hardening' 'AutoRun on removable media' ($(if ($autorun -eq 255) { 'PASS' } else { 'WARN' })) `
    ("NoDriveTypeAutoRun = {0}" -f $(if ($null -eq $autorun) { 'not set' } else { $autorun })) 'Disable AutoRun for all drives (value 255) by GPO.'

# --- Disk encryption --------------------------------------------------------
if ($isAdmin -and (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue)) {
    try {
        $sys = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
        Add-Result 'Encryption' "BitLocker $($env:SystemDrive)" ($(if ($sys.ProtectionStatus -eq 'On') { 'PASS' } else { 'FAIL' })) `
            ("ProtectionStatus = {0}" -f $sys.ProtectionStatus) 'Encrypt the system drive (BitLocker), especially on laptops.'
    } catch {
        Add-Result 'Encryption' 'BitLocker' 'SKIPPED' $_.Exception.Message
    }
} else {
    Add-Result 'Encryption' 'BitLocker' 'SKIPPED' 'Requires administrator rights'
}

# --- Output -----------------------------------------------------------------
$results | Format-Table Category, Check, Status, Detail -AutoSize -Wrap

$counts = $results | Group-Object Status | ForEach-Object { '{0}: {1}' -f $_.Name, $_.Count }
Write-Host ("Summary - {0}" -f ($counts -join ' | '))
if (-not $isAdmin) { Write-Host 'Tip: run as administrator for the full audit.' }

if (-not $NoHtml) {
    $enc = { param($s) [System.Net.WebUtility]::HtmlEncode([string]$s) }
    $rows = foreach ($r in $results) {
        "<tr class='{0}'><td>{1}</td><td>{2}</td><td><b>{3}</b></td><td>{4}</td><td>{5}</td></tr>" -f `
            $r.Status.ToLower(), (& $enc $r.Category), (& $enc $r.Check), $r.Status, (& $enc $r.Detail), (& $enc $r.Recommendation)
    }
    $html = @"
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Security audit - $env:COMPUTERNAME</title>
<style>
 body{font-family:Segoe UI,Arial,sans-serif;margin:32px;color:#1b2333}
 table{border-collapse:collapse;width:100%;font-size:14px}
 th,td{border-bottom:1px solid #dde3ec;padding:8px 10px;text-align:left;vertical-align:top}
 th{background:#f1f4f9}
 .pass b{color:#15803d}.warn b{color:#b45309}.fail b{color:#b91c1c}.info b,.skipped b{color:#64748b}
</style></head><body>
<h1>Security audit - $env:COMPUTERNAME</h1>
<p>$(Get-Date -Format 'yyyy-MM-dd HH:mm') &middot; administrator: $isAdmin &middot; $($counts -join ' | ')</p>
<table><tr><th>Category</th><th>Check</th><th>Status</th><th>Detail</th><th>Recommendation</th></tr>
$($rows -join "`n")
</table></body></html>
"@
    $html | Out-File -FilePath $ReportPath -Encoding utf8
    Write-Host "HTML report: $ReportPath"
}
