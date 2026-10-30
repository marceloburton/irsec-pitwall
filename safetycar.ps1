<#
safetycar.ps1 - IRSeC 2026, Team 10, safetycar (ICMP + Telnet). Also works on teamradio (WinRM).
Author: Marcelo Burton
Public per IRSeC rule 20. Companion to pitwall.ps1 for the non-DC Windows boxes.

  -Setup : run once at the start. Backs up local users, groups, firewall, services, tasks.
           Changes passwords for the packet's local users (you type the new ones).
           Disables Guest, turns on extra logging, turns off SMBv1,
           asks before removing rogue admins or disabling unknown users,
           then runs a hunt.
  -Hunt  : run every 10-15 minutes. Read-only unless you answer y to a prompt.
           Checks the scored services (ping, Telnet, WinRM), then users, admins,
           ports, connections, processes, tasks, services, autostarts, firewall,
           Defender exclusions, hosts file. Shows what's NEW since the last hunt
           and prints the fix command for each item. Saves a copy to C:\Users\Public\bk.

Picks the scored checks from the computer name: safetycar = ping + Telnet,
teamradio = WinRM, anything else = all three. Override with -Box safetycar or -Box teamradio.

Never touches: whiteteam, 10.X.1.99 (NetBird egress), dd-agent, ddagentuser, DataDog, Wazuh, the Telnet service itself.
Never deletes users. Never runs a virus scan (rule 12).

Run in PowerShell as administrator:
  powershell -ExecutionPolicy Bypass -File .\safetycar.ps1 -Setup
  powershell -ExecutionPolicy Bypass -File .\safetycar.ps1 -Hunt
#>
param([switch]$Setup, [switch]$Hunt, [string]$Box)

$ErrorActionPreference = 'Continue'
$BK    = 'C:\Users\Public\bk'
$script:StateDir = Join-Path $BK 'state'

# ---------- Packet lists (IRSeC 2026 packet, Users page: local users) ----------
$LocalAdmins  = @('scrutineer','techdirector','crewchief','firecrew')
$LocalUsers   = @('jackcrew','garagecrew','celebrity','pitlaner','reserve','gunners')
$OutOfScope   = @('whiteteam','dd-agent','ddagentuser')
$BuiltIn      = @('Administrator','Guest','DefaultAccount','WDAGUtilityAccount','defaultuser0')
$KnownUsers   = $LocalAdmins + $LocalUsers + $OutOfScope + $BuiltIn
$AllowedPriv  = $LocalAdmins + @('whiteteam','Administrator','Domain Admins','Enterprise Admins',
                'principal','sportingdir','chiefeng','strategist')
$PrivGroups   = @('Administrators','Remote Desktop Users','Remote Management Users','Backup Operators')

# ---------- What normal looks like ----------
$SusPath   = '\\Users\\|\\ProgramData\\|\\Temp\\|\\Tmp\\|\\AppData\\|\\Windows\\Tasks\\|\\PerfLogs\\|\\Recycle|\\Public\\|\\Downloads\\'
$SusCmd    = '-enc\b|-encodedcommand|frombase64string|downloadstring|downloadfile|invoke-webrequest|\biwr\b|invoke-expression|\biex\b|-w(indowstyle)?\s+hidden|net\.sockets|tcpclient|\bnc(at)?\.exe|\bnc\s+-|mshta|certutil.*-urlcache|bitsadmin.*/transfer'
$ShellRx   = 'powershell|pwsh|cmd\.exe|cmd /c|wscript|cscript|mshta'
$AgentRx   = 'datadog|wazuh|ossec|vmtools|vgauth|vm3d|vmware|qemu|cloudbase|balloon|spice|virtio|xen'
$GoodPath  = '\\ProgramData\\Microsoft\\Windows Defender\\|\\Windows Defender|\\Microsoft\\Edge|\\Microsoft\\EdgeUpdate|\\Microsoft\\EdgeWebView|\\Windows Media Player\\|\\Microsoft Update Health Tools\\|\\Common Files\\microsoft shared\\|\\Internet Explorer\\|\\Windows NT\\Accessories\\|\\AppData\\Local\\Microsoft\\OneDrive\\'
$OkProcs   = @('System','Idle','lsass','svchost','services','wininit','spoolsv','WmiPrvSE','wsmprovhost','msdtc')
$OkPorts   = @(135,139,445,3389,5040,5357,5985,5986,7680,47001)
$OkRootTasks = '^(MicrosoftEdgeUpdate|CreateExplorerShellUnelevatedTask|User_Feed_Synchronization|OneDrive)'
$CritNames = @('svchost.exe','lsass.exe','csrss.exe','winlogon.exe','services.exe','smss.exe','wininit.exe','explorer.exe','spoolsv.exe')
$LookAlike = '^(scvhost|svch0st|svhost|svchosts|svchost32|lsas|lsasss|isass|1sass|csrs|csrsss|winlogin|expl0rer|explore|explorer32|servces|spoolsvc)\.exe$'

if (-not $Box) { $Box = "$env:COMPUTERNAME" }
$Box = $Box.ToLower()
$DoPing   = ($Box -match 'safetycar') -or ($Box -notmatch 'teamradio')
$DoTelnet = $DoPing
$DoWinRM  = ($Box -match 'teamradio') -or ($Box -notmatch 'safetycar')
if ($DoTelnet) { $OkPorts += 23 }

# ---------- Helpers ----------
$script:Flags = New-Object System.Collections.ArrayList
$script:NewItems = @()
$script:AccountIssues = 0
$script:FirstRun = $false
$script:TelnetPid = -1
$script:TelnetProc = ''
$script:TelnetSvc = ''
$script:FwOn = $false
$script:MissingAllow = 0
$script:PF = @{}

function Add-Flag($Level, $What, $Fix) {
    [void]$script:Flags.Add([pscustomobject]@{ Level = $Level; What = $What; Fix = $Fix })
    $c = 'Yellow'; if ($Level -eq 'FLAG') { $c = 'Red' }
    Write-Host ("  [{0}] {1}" -f $Level, $What) -ForegroundColor $c
}
function Section($t) { Write-Host ''; Write-Host ("== {0} ==" -f $t) -ForegroundColor Cyan }
function Ok($t) { Write-Host ("  ok: {0}" -f $t) -ForegroundColor Green }
function Info($t) { Write-Host ("  {0}" -f $t) -ForegroundColor DarkGray }
function Ask($q) { $a = Read-Host "$q (y/n)"; return ($a -match '^(y|yes)$') }

function Compare-State($Name, $Current, $Label) {
    $Current = @($Current | Where-Object { $_ } | Sort-Object -Unique)
    $file = Join-Path $script:StateDir "$Name.txt"
    if (Test-Path $file) {
        $prev = @(Get-Content $file)
        foreach ($n in $Current) { if ($prev -notcontains $n) { $script:NewItems += "NEW  $Label : $n" } }
        foreach ($g in $prev)    { if ($Current -notcontains $g) { $script:NewItems += "GONE $Label : $g" } }
    } else { $script:FirstRun = $true }
    Set-Content -Path $file -Value $Current -Encoding ASCII
}

function Get-ExePath($s) {
    # pull the program path out of a command line
    $s = [Environment]::ExpandEnvironmentVariables([string]$s).Trim()
    if ($s.StartsWith('"')) { return $s.Split('"')[1] }
    if ($s -match '^(.+?\.(exe|dll|bat|cmd|ps1|vbs|js))') { return $Matches[1] }
    return ($s -split ' ')[0]
}

function Get-GroupMembers($Group) {
    # net localgroup works even when Get-LocalGroupMember chokes on orphaned SIDs
    $out = net localgroup "$Group" 2>$null
    $res = @(); $started = $false
    foreach ($line in @($out)) {
        if ($line -match '^-{5,}') { $started = $true; continue }
        if (-not $started) { continue }
        if ($line -match '^The command completed') { break }
        if ("$line".Trim()) { $res += "$line".Trim() }
    }
    return $res
}
function Short($n) { return ([string]$n -split '\\')[-1] }

# ---------- Setup steps ----------
function Do-Backup {
    Section 'Backup (before changing anything)'
    New-Item -ItemType Directory -Force -Path $BK, $script:StateDir | Out-Null
    $t = Get-Date -Format 'MMdd_HHmm'
    try { Get-LocalUser | Select-Object Name, Enabled, LastLogon, Description | Export-Csv (Join-Path $BK "localusers_$t.csv") -NoTypeInformation; Ok "localusers_$t.csv" }
    catch { Write-Host "  user backup failed: $($_.Exception.Message)" -ForegroundColor Red }
    $grp = foreach ($g in $PrivGroups) { "== $g"; Get-GroupMembers $g }
    Set-Content -Path (Join-Path $BK "groups_$t.txt") -Value $grp -Encoding ASCII
    Ok "groups_$t.txt"
    netsh advfirewall export (Join-Path $BK "firewall_$t.wfw") | Out-Null
    Ok "firewall_$t.wfw"
    Get-CimInstance Win32_Service | Select-Object Name, DisplayName, State, StartMode, PathName |
        Export-Csv (Join-Path $BK "services_$t.csv") -NoTypeInformation
    Get-ScheduledTask | Select-Object TaskPath, TaskName, State,
        @{ n = 'Action'; e = { ($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' && ' } } |
        Export-Csv (Join-Path $BK "tasks_$t.csv") -NoTypeInformation
    Ok "services_$t.csv, tasks_$t.csv"
    try {
        $cs = Get-CimInstance Win32_ComputerSystem
        if ($cs.PartOfDomain) { Ok ("joined to domain {0} (domain passwords get changed on pitwall)" -f $cs.Domain) }
        else { Ok 'not domain-joined (local accounts only)' }
    } catch {}
}

function Read-NewPassword($Label) {
    while ($true) {
        $a = Read-Host "  New password for $Label" -AsSecureString
        $b = Read-Host '  Type it again' -AsSecureString
        $pa = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($a))
        $pb = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($b))
        if ($pa -cne $pb) { Write-Host '  They did not match. Try again.' -ForegroundColor Yellow; continue }
        if ($pa.Length -lt 12) { Write-Host '  Use 12+ characters. Try again.' -ForegroundColor Yellow; continue }
        return $a
    }
}

function Set-LocalPasswords($Names, $Secure) {
    foreach ($n in $Names) {
        if (-not (Get-LocalUser -Name $n -ErrorAction SilentlyContinue)) { Info "no local user '$n' on this box"; continue }
        try { Set-LocalUser -Name $n -Password $Secure -ErrorAction Stop; Ok "password changed: $n" }
        catch { Add-Flag 'CHECK' "password NOT changed for $n ($($_.Exception.Message))" "net user $n *" }
    }
}

function Enable-Logging {
    foreach ($cat in 'Account Logon','Account Management','Logon/Logoff','Detailed Tracking','Policy Change','DS Access','System') {
        auditpol /set /category:"$cat" /success:enable /failure:enable | Out-Null
    }
    $k1 = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
    if (-not (Test-Path $k1)) { New-Item -Path $k1 -Force | Out-Null }
    Set-ItemProperty -Path $k1 -Name EnableScriptBlockLogging -Value 1
    $k2 = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
    if (-not (Test-Path $k2)) { New-Item -Path $k2 -Force | Out-Null }
    Set-ItemProperty -Path $k2 -Name ProcessCreationIncludeCmdLine_Enabled -Value 1
    Ok 'audit logging + PowerShell logging + process command lines on'
}

function Fix-Accounts {
    Section 'Rogue accounts (y/n for each - screenshot first)'
    $any = $false
    foreach ($g in $PrivGroups) {
        foreach ($m in @(Get-GroupMembers $g)) {
            if ($AllowedPriv -contains (Short $m)) { continue }
            $any = $true
            if (Ask ("  '{0}' is in {1}. Remove it from {1}?" -f $m, $g)) {
                net localgroup "$g" "$m" /delete | Out-Null
                if ($LASTEXITCODE -eq 0) { Ok "removed $m from $g" } else { Write-Host "  failed to remove $m" -ForegroundColor Red }
            }
        }
    }
    foreach ($u in @(Get-LocalUser | Where-Object { $_.Enabled -and $KnownUsers -notcontains $_.Name })) {
        $any = $true
        if (Ask ("  Unknown local user '{0}'. Disable it?" -f $u.Name)) {
            try { Disable-LocalUser -Name $u.Name -ErrorAction Stop; Ok "disabled $($u.Name)" }
            catch { Write-Host "  failed: $($_.Exception.Message)" -ForegroundColor Red }
        }
    }
    if (-not $any) { Ok 'no rogue admins or unknown users' }
}

# ---------- Scored services ----------
function Load-PortFilters {
    $script:PF = @{}
    Get-NetFirewallPortFilter -All -ErrorAction SilentlyContinue | ForEach-Object { $script:PF[[string]$_.InstanceID] = $_ }
    $script:FwOn = @(Get-NetFirewallProfile | Where-Object { "$($_.Enabled)" -eq 'True' }).Count -gt 0
}

function Test-Allowed($Port, $Proto) {
    foreach ($r in @(Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow -ErrorAction SilentlyContinue)) {
        $f = $script:PF[[string]$r.Name]
        if (-not $f) { continue }
        if ($Proto -eq 'ICMPv4') { if ("$($f.Protocol)" -match '^(ICMPv4|1)$') { return $true } }
        elseif (@($f.LocalPort) -contains "$Port") { return $true }
    }
    return $false
}

function Need-Allow($Label, $Port, $Proto, $Fix) {
    if (Test-Allowed $Port $Proto) { Ok "firewall allow rule exists for $Label"; return }
    $script:MissingAllow++
    if ($script:FwOn) { Add-Flag 'FLAG' "Firewall is ON and nothing allows $Label - that check is blocked" $Fix }
    else { Add-Flag 'CHECK' "No allow rule for $Label yet (firewall is off, so not blocked now). Add it before anyone turns the firewall on" $Fix }
}

function Check-Health {
    Section ("Scored services on {0}" -f $Box)
    Load-PortFilters
    if ($DoPing) {
        Need-Allow 'ping (ICMP)' 0 'ICMPv4' "New-NetFirewallRule -DisplayName 'Allow ping in' -Direction Inbound -Protocol ICMPv4 -IcmpType 8 -Action Allow"
        foreach ($r in @(Get-NetFirewallRule -Enabled True -Direction Inbound -Action Block -ErrorAction SilentlyContinue)) {
            $f = $script:PF[[string]$r.Name]
            if ($f -and "$($f.Protocol)" -match '^(ICMPv4|1)$') { Add-Flag 'FLAG' "Firewall rule '$($r.DisplayName)' BLOCKS ping" ("Disable-NetFirewallRule -Name '{0}'" -f $r.Name) }
        }
    }
    if ($DoTelnet) {
        $l = @(Get-NetTCPConnection -LocalPort 23 -State Listen -ErrorAction SilentlyContinue)
        $ownFile = Join-Path $script:StateDir 'telnet_service.txt'
        if ($l.Count -eq 0) {
            $hint = 'Get-Service *telnet*   (find the Telnet service, then Start-Service it)'
            if (Test-Path $ownFile) { $own = Get-Content $ownFile | Select-Object -First 1; if ($own) { $hint = "Start-Service '$own'   (that service ran Telnet at setup)" } }
            Add-Flag 'FLAG' 'Nothing is listening on port 23 - the Telnet check will fail' $hint
        } else {
            $script:TelnetPid = [int]$l[0].OwningProcess
            $script:TelnetProc = [string](Get-Process -Id $script:TelnetPid -ErrorAction SilentlyContinue).ProcessName
            $svc = @(Get-CimInstance Win32_Service -Filter "ProcessId=$($script:TelnetPid)" -ErrorAction SilentlyContinue)
            if ($svc.Count -gt 0) { $script:TelnetSvc = $svc[0].Name; Set-Content -Path $ownFile -Value $svc[0].Name -Encoding ASCII }
            Ok ("Telnet listening on 23: {0} (PID {1}, service {2}). That's the scored service - don't kill it." -f $script:TelnetProc, $script:TelnetPid, $script:TelnetSvc)
        }
        Need-Allow 'Telnet (TCP 23)' 23 'TCP' "New-NetFirewallRule -DisplayName 'Allow Telnet 23' -Direction Inbound -Protocol TCP -LocalPort 23 -Action Allow"
    }
    if ($DoWinRM) {
        $w = Get-Service -Name WinRM -ErrorAction SilentlyContinue
        if (-not $w) { Add-Flag 'FLAG' 'WinRM service not found' 'Get-Service *winrm*' }
        elseif ($w.Status -ne 'Running') { Add-Flag 'FLAG' "WinRM service is $($w.Status)" 'Set-Service WinRM -StartupType Automatic; Start-Service WinRM' }
        else { Ok 'WinRM service running' }
        if (@(Get-NetTCPConnection -LocalPort 5985 -State Listen -ErrorAction SilentlyContinue).Count -eq 0) {
            Add-Flag 'FLAG' 'Nothing is listening on port 5985 - the WinRM check will fail' 'Start-Service WinRM; then: winrm enumerate winrm/config/listener   (no listener? ask white team)'
        } else { Ok 'port 5985 listening' }
        Need-Allow 'WinRM (TCP 5985)' 5985 'TCP' "New-NetFirewallRule -DisplayName 'Allow WinRM 5985' -Direction Inbound -Protocol TCP -LocalPort 5985 -Action Allow"
    }
}

# ---------- Hunt checks ----------
function Check-Users {
    Section 'Local users'
    $users = @(Get-LocalUser)
    foreach ($u in $users) {
        $n = $u.Name
        if ($KnownUsers -notcontains $n) {
            if ($u.Enabled) { $script:AccountIssues++; Add-Flag 'FLAG' "Unknown local user '$n' is ENABLED" "Disable-LocalUser -Name '$n'" }
            else { Info "unknown user '$n' is already disabled" }
        }
        elseif (($LocalAdmins + $LocalUsers) -contains $n -and -not $u.Enabled) {
            Add-Flag 'CHECK' "Packet user '$n' is DISABLED (a score check may need it)" "Enable-LocalUser -Name '$n'"
        }
        if ($n -eq 'Guest' -and $u.Enabled) { Add-Flag 'FLAG' 'Guest is enabled' "Disable-LocalUser -Name 'Guest'" }
    }
    Ok ("{0} local users checked" -f $users.Count)
    Compare-State 'users' ($users | ForEach-Object { $_.Name }) 'local user'
}

function Check-PrivGroups {
    Section 'Admin groups'
    $state = @()
    foreach ($g in $PrivGroups) {
        $members = @(Get-GroupMembers $g)
        foreach ($m in $members) {
            $state += "$g : $m"
            if ($AllowedPriv -notcontains (Short $m)) {
                $script:AccountIssues++
                Add-Flag 'FLAG' ("'{0}' is in {1} (not allowed by the packet)" -f $m, $g) ("net localgroup `"{0}`" `"{1}`" /delete" -f $g, $m)
            }
        }
        if ($members.Count -gt 0) { Info ("{0}: {1}" -f $g, ($members -join ', ')) }
    }
    Compare-State 'admins' $state 'admin membership'
}

function Get-ProcTable {
    $t = @{}
    Get-Process -ErrorAction SilentlyContinue | ForEach-Object { $t[[int]$_.Id] = $_ }
    return $t
}

function Check-Ports {
    Section 'Listening ports'
    $procs = Get-ProcTable
    $state = @()
    $listen = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Sort-Object LocalPort -Unique)
    foreach ($c in $listen) {
        $procId = [int]$c.OwningProcess
        $p = $procs[$procId]; $pn = '?'; $pp = ''
        if ($p) { $pn = $p.ProcessName; $pp = [string]$p.Path }
        $state += "$($c.LocalPort) $pn"
        if ($pp -match $AgentRx -or $pn -match $AgentRx) { continue }
        $okProc = ($OkProcs -contains $pn) -or ($script:TelnetPid -eq $procId)
        $okPort = ($OkPorts -contains [int]$c.LocalPort) -or ([int]$c.LocalPort -ge 49152)
        if ($okProc -and $okPort) { continue }
        $lvl = 'CHECK'; if (-not $okProc) { $lvl = 'FLAG' }
        $fix = "Stop-Process -Id $procId -Force   (then find what starts it: tasks, services, Run keys)"
        if ($pn -eq 'svchost') { $fix = "Get-CimInstance Win32_Service -Filter 'ProcessId=$procId' | Select Name,PathName   (find the service, then stop + disable it)" }
        Add-Flag $lvl ("Port {0} listening: {1} (PID {2}) {3}" -f $c.LocalPort, $pn, $procId, $pp) $fix
    }
    Ok ("{0} listening ports checked" -f $listen.Count)
    Compare-State 'ports' $state 'listening port'
}

function Check-Connections {
    Section 'Outside connections'
    $procs = Get-ProcTable
    $bad = '^(powershell|pwsh|cmd|rundll32|regsvr32|mshta|wscript|cscript|nc|ncat|python|python3|java|certutil|bitsadmin)$'
    $est = @(Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Where-Object {
        $_.RemoteAddress -notmatch '^(127\.|::1$|0\.0\.0\.0)' -and $_.RemoteAddress -ne $_.LocalAddress })
    foreach ($c in $est) {
        $procId = [int]$c.OwningProcess
        if ($procId -eq $script:TelnetPid) { continue }
        $p = $procs[$procId]; $pn = '?'; $pp = ''
        if ($p) { $pn = $p.ProcessName; $pp = [string]$p.Path }
        if ($pp -match $AgentRx -or $pn -match $AgentRx -or $pp -match $GoodPath) { continue }
        $what = "{0} (PID {1}) connected to {2}:{3}" -f $pn, $procId, $c.RemoteAddress, $c.RemotePort
        $blockFix = "Stop-Process -Id $procId -Force   (then block the IP: New-NetFirewallRule -DisplayName 'block $($c.RemoteAddress)' -Direction Outbound -RemoteAddress $($c.RemoteAddress) -Action Block)"
        if ($c.RemoteAddress -match '^10\.\d+\.1\.99$') { $blockFix = "Stop-Process -Id $procId -Force   (do NOT block $($c.RemoteAddress): NetBird egress host, out of scope per packet V2)" }
        if ($pn -match $bad -or $pp -match $SusPath) { Add-Flag 'FLAG' $what $blockFix }
        elseif ($OkProcs -notcontains $pn) { Add-Flag 'CHECK' "$what $pp" "Get-Process -Id $procId | Select Name,Path   (Google the name if unsure)" }
    }
    Ok ("{0} outside connections checked" -f $est.Count)
}

function Check-Processes {
    Section 'Running processes'
    $all = @(Get-CimInstance Win32_Process)
    foreach ($p in $all) {
        if ($p.ProcessId -eq $PID) { continue }
        if ($p.ProcessId -eq $script:TelnetPid) { continue }
        $path = [string]$p.ExecutablePath; $cmd = [string]$p.CommandLine; $name = [string]$p.Name
        if ($cmd -match 'pitwall\.ps1') { continue }
        if ($path -match $GoodPath -or $path -match $AgentRx) { continue }
        $why = @()
        if ($path -match $SusPath) { $why += 'runs from a user/temp folder' }
        if ($cmd -match $SusCmd) { $why += 'suspicious command line' }
        if ($name -match $LookAlike) { $why += 'look-alike of a Windows name' }
        if ($CritNames -contains $name.ToLower() -and $path -and $path -notmatch '^C:\\Windows\\') { $why += 'Windows name outside C:\Windows' }
        if ($why.Count -eq 0) { continue }
        $short = $cmd; if ($short.Length -gt 160) { $short = $short.Substring(0, 160) + '...' }
        $fix = "Stop-Process -Id $($p.ProcessId) -Force"
        if ($path -and $path -notmatch '^C:\\Windows\\') { $fix += "; Remove-Item '$path' -Force" }
        $fix += '   (then find what starts it)'
        Add-Flag 'FLAG' ("Process {0} PID {1} (parent {2}): {3}. path={4} cmd={5}" -f $name, $p.ProcessId, $p.ParentProcessId, ($why -join ', '), $path, $short) $fix
    }
    Ok ("{0} processes checked" -f $all.Count)
}

function Check-Tasks {
    Section 'Scheduled tasks'
    $state = @()
    $tasks = @(Get-ScheduledTask -ErrorAction SilentlyContinue)
    foreach ($t in $tasks) {
        $state += "$($t.TaskPath)$($t.TaskName)"
        $acts = (@($t.Actions | ForEach-Object { ("{0} {1}" -f $_.Execute, $_.Arguments).Trim() }) -join ' && ')
        $exe  = Get-ExePath (@($t.Actions | ForEach-Object { $_.Execute }) | Select-Object -First 1)
        if ($acts -match $AgentRx -or $t.TaskName -match $AgentRx -or $exe -match $GoodPath) { continue }
        $isMs = $t.TaskPath -like '\Microsoft\*'
        if ($t.TaskPath -eq '\' -and $t.TaskName -match $OkRootTasks) { continue }
        $hardSus = ($exe -match $SusPath) -or ($acts -match $SusCmd)
        if ($isMs -and -not $hardSus) { continue }
        $lvl = 'CHECK'; if ($hardSus -or $acts -match $ShellRx) { $lvl = 'FLAG' }
        $fix = "Disable-ScheduledTask -TaskName '{0}' -TaskPath '{1}'; Unregister-ScheduledTask -TaskName '{0}' -TaskPath '{1}' -Confirm:`$false" -f $t.TaskName, $t.TaskPath
        if ($exe -match '\\' -and $exe -notmatch '^C:\\Windows\\' -and $exe -notmatch $ShellRx) { $fix += "; Remove-Item '$exe' -Force" }
        elseif ($acts -match $ShellRx) { $fix += '   (the payload file is in the arguments - delete that file too)' }
        Add-Flag $lvl ("Task {0}{1} [{2}] runs: {3}" -f $t.TaskPath, $t.TaskName, $t.State, $acts) $fix
    }
    Ok ("{0} tasks checked" -f $tasks.Count)
    Compare-State 'tasks' $state 'scheduled task'
}

function Check-Services {
    Section 'Services'
    $state = @()
    $svcs = @(Get-CimInstance Win32_Service)
    foreach ($s in $svcs) {
        $state += $s.Name
        if ($script:TelnetSvc -and $s.Name -eq $script:TelnetSvc) { continue }
        $pn = [string]$s.PathName
        if ($s.Name -match $AgentRx -or $pn -match $AgentRx -or $s.DisplayName -match $AgentRx -or $pn -match $GoodPath) { continue }
        $winPath = ($pn -match '^"?C:\\Windows\\') -or ($pn -match '^"?%SystemRoot%') -or ($pn -match '^"?\\SystemRoot\\') -or ($pn -match '^"?system32\\')
        $sus = ($pn -match $SusPath) -or ($pn -match $SusCmd) -or ($pn -match $ShellRx)
        if ($winPath -and -not $sus) { continue }
        $lvl = 'CHECK'; if ($sus) { $lvl = 'FLAG' }
        $fix = "Stop-Service -Name '{0}' -Force; Set-Service -Name '{0}' -StartupType Disabled" -f $s.Name
        $exe = Get-ExePath $pn
        if ($sus -and $exe -match '\\' -and $exe -notmatch '^C:\\Windows\\' -and $exe -notmatch $ShellRx) { $fix += "; Remove-Item '$exe' -Force" }
        Add-Flag $lvl ("Service {0} ({1}) {2}/{3} path={4}" -f $s.Name, $s.DisplayName, $s.State, $s.StartMode, $pn) $fix
    }
    Ok ("{0} services checked" -f $svcs.Count)
    Compare-State 'services' $state 'service'
}

function Check-Autostarts {
    Section 'Run keys, Winlogon, IFEO, Startup folders'
    $state = @()
    $keys = @('HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
              'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
              'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
              'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
              'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
              'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce')
    foreach ($k in $keys) {
        if (-not (Test-Path $k)) { continue }
        $item = Get-ItemProperty -Path $k
        foreach ($prop in $item.PSObject.Properties) {
            if ($prop.Name -like 'PS*') { continue }
            $v = [string]$prop.Value
            $state += "$k : $($prop.Name)"
            if ($v -match $AgentRx -or $prop.Name -match 'SecurityHealth|VMware|OneDrive') { continue }
            $lvl = 'CHECK'; if ($v -match $SusPath -or $v -match $SusCmd -or $v -match $ShellRx) { $lvl = 'FLAG' }
            Add-Flag $lvl ("Run key {0} : {1} = {2}" -f $k, $prop.Name, $v) ("Remove-ItemProperty -Path '{0}' -Name '{1}'" -f $k, $prop.Name)
        }
    }
    $wlk = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    $wl = Get-ItemProperty -Path $wlk
    if ($wl.Userinit -and ([string]$wl.Userinit).TrimEnd(',').ToLower() -ne 'c:\windows\system32\userinit.exe') {
        Add-Flag 'FLAG' "Winlogon Userinit changed: $($wl.Userinit)" "Set-ItemProperty -Path '$wlk' -Name Userinit -Value 'C:\Windows\system32\userinit.exe,'"
    }
    if ($wl.Shell -and ([string]$wl.Shell).ToLower() -ne 'explorer.exe') {
        Add-Flag 'CHECK' "Winlogon Shell is: $($wl.Shell)" "Set-ItemProperty -Path '$wlk' -Name Shell -Value 'explorer.exe'"
    }
    $ifeo = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
    Get-ChildItem -Path $ifeo -ErrorAction SilentlyContinue | ForEach-Object {
        $d = (Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue).Debugger
        if ($d) { Add-Flag 'FLAG' ("IFEO debugger on {0} -> {1} (sticky-keys style backdoor)" -f $_.PSChildName, $d) ("Remove-ItemProperty -Path '{0}\{1}' -Name Debugger" -f $ifeo, $_.PSChildName) }
    }
    $folders = @('C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp')
    if (Test-Path 'C:\Users') {
    $folders += @(Get-ChildItem 'C:\Users' -Directory -Force -ErrorAction SilentlyContinue | ForEach-Object { Join-Path $_.FullName 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup' })
    }
    foreach ($f in $folders) {
        if (-not (Test-Path $f)) { continue }
        foreach ($file in @(Get-ChildItem -Path $f -File -Force -ErrorAction SilentlyContinue)) {
            if ($file.Name -eq 'desktop.ini') { continue }
            $state += $file.FullName
            Add-Flag 'FLAG' "Startup folder file: $($file.FullName)" "Remove-Item '$($file.FullName)' -Force"
        }
    }
    Ok 'autostart locations checked'
    Compare-State 'autostarts' $state 'autostart'
}

function Check-Firewall([bool]$OfferFix) {
    Section 'Firewall'
    $off = @(Get-NetFirewallProfile | Where-Object { "$($_.Enabled)" -eq 'False' })
    if ($off.Count -gt 0) {
        $names = ($off | ForEach-Object { $_.Name }) -join ', '
        if ($script:MissingAllow -eq 0) {
            if ($OfferFix -and (Ask "  Firewall is OFF for: $names. Allow rules for your scored services exist. Turn it ON?")) {
                Set-NetFirewallProfile -All -Enabled True; Ok 'firewall on (check Hermes in 1 minute)'
            } else { Add-Flag 'CHECK' "Firewall is OFF for: $names" 'Set-NetFirewallProfile -All -Enabled True   (then check Hermes)' }
        } else { Add-Flag 'CHECK' "Firewall is OFF for: $names - add the missing allow rules above BEFORE turning it on" 'run the New-NetFirewallRule fixes above first' }
    } else { Ok 'all firewall profiles on' }
    $state = @()
    $custom = @(Get-NetFirewallRule -Enabled True -ErrorAction SilentlyContinue | Where-Object { [string]::IsNullOrEmpty($_.DisplayGroup) })
    foreach ($r in $custom) {
        $state += "$($r.DisplayName) [$($r.Direction) $($r.Action)]"
        if ($r.DisplayName -match $AgentRx -or $r.DisplayName -match '^Allow (ping in|Telnet 23|WinRM 5985)$') { continue }
        $pf = $r | Get-NetFirewallPortFilter
        $af = $r | Get-NetFirewallApplicationFilter
        $ad = $r | Get-NetFirewallAddressFilter
        $desc = "'{0}' {1} {2} | program={3} | local port={4} | remote port={5} | remote IP={6}" -f $r.DisplayName, $r.Direction, $r.Action, $af.Program, ($pf.LocalPort -join ','), ($pf.RemotePort -join ','), ($ad.RemoteAddress -join ',')
        $lvl = 'CHECK'; if ("$($r.Action)" -eq 'Allow' -and ($af.Program -match $SusPath -or "$($r.Direction)" -eq 'Outbound')) { $lvl = 'FLAG' }
        Add-Flag $lvl "Custom firewall rule (not a Windows built-in; teammates' rules show here too): $desc" ("Disable-NetFirewallRule -Name '{0}'" -f $r.Name)
    }
    Compare-State 'fwrules' $state 'firewall rule'
}

function Check-Defender {
    Section 'Defender exclusions (look only - rule 12)'
    try {
        $mp = Get-MpPreference -ErrorAction Stop
        $ex = @($mp.ExclusionPath) + @($mp.ExclusionProcess) + @($mp.ExclusionExtension) | Where-Object { $_ }
        foreach ($e in $ex) { Add-Flag 'FLAG' "Defender exclusion: $e (red team hides files here - go look)" 'Look at that folder/file and screenshot it. Ask white team before changing Defender.' }
        if ($ex.Count -eq 0) { Ok 'no exclusions' }
    } catch { Info 'Defender not available' }
}

function Check-Hosts {
    Section 'hosts file'
    $lines = @(Get-Content "$env:windir\System32\drivers\etc\hosts" -ErrorAction SilentlyContinue | Where-Object { $_ -and $_.Trim() -and $_.Trim() -notmatch '^#' })
    foreach ($l in $lines) { Add-Flag 'CHECK' "hosts file entry: $l" 'notepad C:\Windows\System32\drivers\etc\hosts   (delete the line, save)' }
    if ($lines.Count -eq 0) { Ok 'hosts file clean' }
}

function Show-Sessions {
    Section 'Who is logged in'
    try { $q = quser 2>$null; if ($q) { $q | ForEach-Object { Info $_ } } else { Info 'no sessions listed' } } catch { Info 'quser not available' }
}

function Run-Hunt {
    $script:Flags.Clear(); $script:NewItems = @(); $script:AccountIssues = 0; $script:FirstRun = $false; $script:MissingAllow = 0
    Write-Host ''
    Write-Host ("{0} hunt - {1}" -f $Box, (Get-Date -Format 'HH:mm')) -ForegroundColor Cyan
    Check-Health; Check-Users; Check-PrivGroups; Check-Ports; Check-Connections; Check-Processes
    Check-Tasks; Check-Services; Check-Autostarts; Check-Firewall ([bool]$Setup); Check-Defender
    Check-Hosts; Show-Sessions

    Section 'CHANGED SINCE LAST HUNT'
    if ($script:FirstRun) { Info 'first hunt - saved a baseline. Next hunt shows what changed.' }
    elseif ($script:NewItems.Count -eq 0) { Ok 'nothing new' }
    else { foreach ($n in $script:NewItems) { Write-Host "  $n" -ForegroundColor Magenta } }

    Section 'TO DO  (FLAG = almost surely red team or a broken check, CHECK = look at it, may be fine)'
    $list = @($script:Flags | Where-Object { $_.Level -eq 'FLAG' }) + @($script:Flags | Where-Object { $_.Level -eq 'CHECK' })
    if ($list.Count -eq 0) { Ok 'nothing flagged' }
    $i = 0
    foreach ($f in $list) {
        $i++
        $c = 'Yellow'; if ($f.Level -eq 'FLAG') { $c = 'Red' }
        Write-Host ("{0}. [{1}] {2}" -f $i, $f.Level, $f.What) -ForegroundColor $c
        Write-Host ("   FIX: {0}" -f $f.Fix)
    }
    Write-Host ''
    Write-Host 'Each item: screenshot -> note row in the team doc -> run the FIX -> one line in Discord -> hunt again in 10 min.' -ForegroundColor Cyan
    Write-Host "Saved to: $script:Log" -ForegroundColor DarkGray
    if ($script:AccountIssues -gt 0 -and (Ask 'Walk through the user/admin fixes now?')) { Fix-Accounts }
}

# ---------- Main ----------
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not ($Setup -or $Hunt)) {
    Write-Host 'safetycar.ps1 - IRSeC 2026 Team 10 helper for safetycar (ping + Telnet) and teamradio (WinRM)'
    Write-Host '  -Setup  once at the start: backup, passwords, quick hardening, then a hunt'
    Write-Host '  -Hunt   every 10-15 min: scored-service checks, read-only hunt, fix commands'
    Write-Host '  powershell -ExecutionPolicy Bypass -File .\safetycar.ps1 -Setup'
    exit
}
if (-not $isAdmin) { Write-Host 'Run PowerShell as Administrator.' -ForegroundColor Red; exit 1 }

New-Item -ItemType Directory -Force -Path $BK, $script:StateDir | Out-Null
$mode = 'hunt'; if ($Setup) { $mode = 'setup' }
$script:Log = Join-Path $BK ("{0}_{1}_{2}.txt" -f $Box, $mode, (Get-Date -Format 'MMdd_HHmm'))
Start-Transcript -Path $script:Log -Append | Out-Null

if ($Setup) {
    Write-Host ("{0} setup" -f $Box) -ForegroundColor Cyan
    Do-Backup
    Check-Health

    Section 'Passwords'
    Write-Host '  First: Hermes > Checks. Note which account the Telnet / WinRM check logs in with.' -ForegroundColor Yellow
    if (Ask '  Change local passwords now?') {
        $adminPw = Read-NewPassword 'the local admins (scrutineer, techdirector, crewchief, firecrew) + Administrator'
        Set-LocalPasswords ($LocalAdmins + @('Administrator')) $adminPw
        $userPw = Read-NewPassword 'the local regular users'
        Set-LocalPasswords $LocalUsers $userPw
        Write-Host '  Put both passwords in the team password sheet NOW.' -ForegroundColor Yellow
        Write-Host '  If a Hermes check logs in with one of these accounts, update it in Hermes > Checks.' -ForegroundColor Yellow
    }

    Section 'Quick hardening'
    try { Disable-LocalUser -Name 'Guest' -ErrorAction Stop; Ok 'Guest disabled' } catch { Info "Guest: $($_.Exception.Message)" }
    Enable-Logging
    try { Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction Stop; Ok 'SMBv1 off' } catch { Info "SMBv1: $($_.Exception.Message)" }

    Fix-Accounts
}

Run-Hunt
Stop-Transcript | Out-Null
