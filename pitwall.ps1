<#
pitwall.ps1 - IRSeC 2026, Team 10, pitwall (domain controller: AD + DNS)
Author: Marcelo Burton
Public per IRSeC rule 20.

  -Setup : run once at the start. Backs up AD, DNS, GPOs, and the firewall.
           Changes passwords for the packet users (you type the new ones).
           Disables Guest, turns on extra logging, turns off SMBv1,
           asks before removing rogue admins or disabling unknown users,
           then runs a hunt.
  -Hunt  : run every 10-15 minutes. Read-only unless you answer y to a prompt.
           Lists anything that doesn't match the packet or a normal DC,
           shows what's NEW since the last hunt, and prints the fix
           command for each item. Saves a copy to C:\Users\Public\bk.

Never touches: whiteteam, 10.X.1.99 (NetBird egress), krbtgt, dd-agent, ddagentuser, DataDog, Wazuh.
Never deletes users. Never runs a virus scan (rule 12).

Run in PowerShell as administrator:
  powershell -ExecutionPolicy Bypass -File .\pitwall.ps1 -Setup
  powershell -ExecutionPolicy Bypass -File .\pitwall.ps1 -Hunt
#>
param([switch]$Setup, [switch]$Hunt)

$ErrorActionPreference = 'Continue'
$BK    = 'C:\Users\Public\bk'
$script:StateDir = Join-Path $BK 'state'

# ---------- Packet lists (IRSeC 2026 packet, Users page) ----------
$PacketAdmins = @('principal','sportingdir','chiefeng','strategist')
$PacketUsers  = @('pitcrew','mechanic','analyst','driver','tireman','fuelman')
$OutOfScope   = @('whiteteam','krbtgt','dd-agent','ddagentuser')
$BuiltIn      = @('Administrator','Guest','DefaultAccount')
$KnownUsers   = $PacketAdmins + $PacketUsers + $OutOfScope + $BuiltIn
$AllowedPriv  = $PacketAdmins + @('whiteteam','Administrator','Domain Admins','Enterprise Admins')
$PrivGroups   = @('Domain Admins','Enterprise Admins','Schema Admins','Administrators',
                  'Group Policy Creator Owners','DnsAdmins','Account Operators','Backup Operators',
                  'Server Operators','Print Operators','Remote Desktop Users','Remote Management Users')

# ---------- What normal looks like ----------
$SusPath   = '\\Users\\|\\ProgramData\\|\\Temp\\|\\Tmp\\|\\AppData\\|\\Windows\\Tasks\\|\\PerfLogs\\|\\Recycle|\\Public\\|\\Downloads\\'
$SusCmd    = '-enc\b|-encodedcommand|frombase64string|downloadstring|downloadfile|invoke-webrequest|\biwr\b|invoke-expression|\biex\b|-w(indowstyle)?\s+hidden|net\.sockets|tcpclient|\bnc(at)?\.exe|\bnc\s+-|mshta|certutil.*-urlcache|bitsadmin.*/transfer'
$ShellRx   = 'powershell|pwsh|cmd\.exe|cmd /c|wscript|cscript|mshta'
$AgentRx   = 'datadog|wazuh|ossec|vmtools|vgauth|vm3d|vmware|qemu|cloudbase|balloon|spice|virtio|xen'
$GoodPath  = '\\ProgramData\\Microsoft\\Windows Defender\\|\\Windows Defender|\\Microsoft\\Edge|\\Microsoft\\EdgeUpdate|\\Microsoft\\EdgeWebView'
$OkProcs   = @('System','Idle','lsass','svchost','services','wininit','spoolsv','dns','dfsrs','ismserv','dfssvc',
               'Microsoft.ActiveDirectory.WebServices','certsrv','vds','WmiPrvSE','wsmprovhost','msdtc')
$OkPorts   = @(53,88,135,139,389,445,464,593,636,3268,3269,3389,5985,5986,9389,47001)
$OkRootTasks = '^(MicrosoftEdgeUpdate|CreateExplorerShellUnelevatedTask|User_Feed_Synchronization)'
$CritNames = @('svchost.exe','lsass.exe','csrss.exe','winlogon.exe','services.exe','smss.exe','wininit.exe','explorer.exe','spoolsv.exe')
$LookAlike = '^(scvhost|svch0st|svhost|svchosts|svchost32|lsas|lsasss|isass|1sass|csrs|csrsss|winlogin|expl0rer|explore|explorer32|servces|spoolsvc)\.exe$'

# ---------- Helpers ----------
$script:Flags = New-Object System.Collections.ArrayList
$script:NewItems = @()
$script:AccountIssues = 0
$script:FirstRun = $false

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

# ---------- Setup steps ----------
function Do-Backup {
    Section 'Backup (before changing anything)'
    New-Item -ItemType Directory -Force -Path $BK, $script:StateDir, (Join-Path $BK 'gpo') | Out-Null
    $t = Get-Date -Format 'MMdd_HHmm'
    try {
        Get-ADUser -Filter * -Properties Enabled, whenCreated, MemberOf |
            Select-Object SamAccountName, Enabled, whenCreated,
                @{ n = 'Groups'; e = { ($_.MemberOf | ForEach-Object { ($_ -split ',')[0] -replace '^CN=' }) -join ';' } } |
            Export-Csv (Join-Path $BK "users_$t.csv") -NoTypeInformation
        Ok "users_$t.csv"
    } catch { Write-Host "  users backup failed: $($_.Exception.Message)" -ForegroundColor Red }
    try { Backup-GPO -All -Path (Join-Path $BK 'gpo') -ErrorAction Stop | Out-Null; Ok 'GPOs -> bk\gpo' }
    catch { Write-Host "  GPO backup failed: $($_.Exception.Message)" -ForegroundColor Red }
    try {
        Get-DnsServerResourceRecord -ZoneName $Zone -RRType A -ErrorAction Stop |
            Select-Object HostName, @{ n = 'IP'; e = { $_.RecordData.IPv4Address.IPAddressToString } } |
            Export-Csv (Join-Path $BK 'dns_A.csv') -NoTypeInformation
        Get-DnsServerResourceRecord -ZoneName $Zone | Out-File (Join-Path $BK "dns_all_$t.txt") -Width 200
        $zf = 'bk_{0}_{1}.dns' -f $Zone, $t
        Export-DnsServerZone -Name $Zone -FileName $zf -ErrorAction Stop
        Copy-Item (Join-Path "$env:windir\System32\dns" $zf) $BK -ErrorAction SilentlyContinue
        Ok "dns_A.csv + zone export ($zf)"
    } catch { Write-Host "  DNS backup failed: $($_.Exception.Message)" -ForegroundColor Red }
    netsh advfirewall export (Join-Path $BK "firewall_$t.wfw") | Out-Null
    Ok "firewall_$t.wfw"
    Get-CimInstance Win32_Service | Select-Object Name, DisplayName, State, StartMode, PathName |
        Export-Csv (Join-Path $BK "services_$t.csv") -NoTypeInformation
    Get-ScheduledTask | Select-Object TaskPath, TaskName, State,
        @{ n = 'Action'; e = { ($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' && ' } } |
        Export-Csv (Join-Path $BK "tasks_$t.csv") -NoTypeInformation
    Ok "services_$t.csv, tasks_$t.csv"
    try {
        $pcs = Get-ADComputer -Filter * | Select-Object -ExpandProperty Name
        Ok ("domain-joined computers: {0}  (post this list for the team)" -f ($pcs -join ', '))
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

function Set-Passwords($Names, $Secure) {
    foreach ($n in $Names) {
        try { Set-ADAccountPassword -Identity $n -Reset -NewPassword $Secure -ErrorAction Stop; Ok "password changed: $n" }
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
        try { $members = @(Get-ADGroupMember -Identity $g -ErrorAction Stop) } catch { continue }
        foreach ($m in $members) {
            if ($AllowedPriv -contains $m.SamAccountName) { continue }
            $any = $true
            if (Ask ("  '{0}' is in {1}. Remove it from {1}?" -f $m.SamAccountName, $g)) {
                try { Remove-ADGroupMember -Identity $g -Members $m.SamAccountName -Confirm:$false -ErrorAction Stop; Ok "removed $($m.SamAccountName) from $g" }
                catch { Write-Host "  failed: $($_.Exception.Message)" -ForegroundColor Red }
            }
        }
    }
    $users = @(Get-ADUser -Filter * -Properties whenCreated | Where-Object {
        -not $_.SamAccountName.EndsWith('$') -and $KnownUsers -notcontains $_.SamAccountName -and $_.Enabled })
    foreach ($u in $users) {
        $any = $true
        if (Ask ("  Unknown user '{0}' (created {1}). Disable it?" -f $u.SamAccountName, $u.whenCreated)) {
            try { Disable-ADAccount -Identity $u.SamAccountName -ErrorAction Stop; Ok "disabled $($u.SamAccountName)" }
            catch { Write-Host "  failed: $($_.Exception.Message)" -ForegroundColor Red }
        }
    }
    if (-not $any) { Ok 'no rogue admins or unknown users' }
}

# ---------- Hunt checks ----------
function Check-Health {
    Section 'AD + DNS health'
    foreach ($s in 'NTDS','DNS','Netlogon','KDC','ADWS','W32Time') {
        $svc = Get-Service -Name $s -ErrorAction SilentlyContinue
        if (-not $svc) { Add-Flag 'FLAG' "Service $s not found" "Get-Service *$s*" }
        elseif ($svc.Status -ne 'Running') { Add-Flag 'FLAG' "Service $s is $($svc.Status)" "Set-Service $s -StartupType Automatic; Start-Service $s" }
        else { Ok "$s running" }
    }
    try { $null = Resolve-DnsName -Name $Zone -Server 127.0.0.1 -DnsOnly -ErrorAction Stop; Ok "DNS answers for $Zone" }
    catch { Add-Flag 'FLAG' "DNS did not answer for $Zone" 'Start-Service DNS; then check firewall rules for port 53' }
    try { $null = Resolve-DnsName -Name "_ldap._tcp.dc._msdcs.$Zone" -Type SRV -Server 127.0.0.1 -DnsOnly -ErrorAction Stop; Ok 'DC SRV records present' }
    catch { Add-Flag 'FLAG' 'DC SRV records missing (domain logins will break)' 'Restart-Service Netlogon; ipconfig /registerdns' }
}

function Check-Users {
    Section 'Domain users'
    $users = @(Get-ADUser -Filter * -Properties Enabled, whenCreated, LockedOut)
    foreach ($u in $users) {
        $n = $u.SamAccountName
        if ($n.EndsWith('$')) { continue }
        if ($KnownUsers -notcontains $n) {
            if ($u.Enabled) {
                $script:AccountIssues++
                Add-Flag 'FLAG' ("Unknown user '{0}' is ENABLED (created {1})" -f $n, $u.whenCreated) ("Disable-ADAccount -Identity '{0}'" -f $n)
            } else { Info "unknown user '$n' is already disabled" }
        }
        elseif (($PacketAdmins + $PacketUsers) -contains $n -and -not $u.Enabled) {
            Add-Flag 'CHECK' "Packet user '$n' is DISABLED (a score check may need it)" "Enable-ADAccount -Identity '$n'"
        }
        if ($u.LockedOut) { Add-Flag 'CHECK' "User '$n' is locked out" "Unlock-ADAccount -Identity '$n'" }
        if ($n -eq 'Guest' -and $u.Enabled) { Add-Flag 'FLAG' 'Guest is enabled' "Disable-ADAccount -Identity 'Guest'" }
    }
    Ok ("{0} user accounts checked" -f $users.Count)
    Compare-State 'users' ($users | ForEach-Object { $_.SamAccountName }) 'user'
}

function Check-PrivGroups {
    Section 'Admin groups'
    $state = @()
    foreach ($g in $PrivGroups) {
        try { $members = @(Get-ADGroupMember -Identity $g -ErrorAction Stop) } catch { continue }
        foreach ($m in $members) {
            $state += "$g : $($m.SamAccountName)"
            if ($AllowedPriv -notcontains $m.SamAccountName) {
                $script:AccountIssues++
                Add-Flag 'FLAG' ("'{0}' is in {1} (not allowed by the packet)" -f $m.SamAccountName, $g) ("Remove-ADGroupMember -Identity '{0}' -Members '{1}' -Confirm:`$false" -f $g, $m.SamAccountName)
            }
        }
        if ($members.Count -gt 0) { Info ("{0}: {1}" -f $g, (($members | ForEach-Object { $_.SamAccountName }) -join ', ')) }
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
        $okProc = $OkProcs -contains $pn
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
        $p = $procs[$procId]; $pn = '?'; $pp = ''
        if ($p) { $pn = $p.ProcessName; $pp = [string]$p.Path }
        if ($pp -match $AgentRx -or $pn -match $AgentRx) { continue }
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
        if ($acts -match $AgentRx -or $t.TaskName -match $AgentRx) { continue }
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
            if ($v -match $AgentRx -or $prop.Name -match 'SecurityHealth|VMware') { continue }
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
    $inAllow = @(Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow -ErrorAction SilentlyContinue)
    # AD and DNS need these ports allowed in: 53 DNS, 88 Kerberos, 389 LDAP
    $pfAll = @{}
    Get-NetFirewallPortFilter -All -ErrorAction SilentlyContinue | ForEach-Object { $pfAll[[string]$_.InstanceID] = @($_.LocalPort) }
    $missing = @()
    foreach ($port in 53, 88, 389) {
        $hit = @($inAllow | Where-Object { $pfAll[[string]$_.Name] -contains "$port" })
        if ($hit.Count -eq 0) { $missing += $port }
    }
    foreach ($m in $missing) {
        Add-Flag 'FLAG' "No enabled inbound allow rule for port $m (AD/DNS need it)" ("New-NetFirewallRule -DisplayName 'Allow {0} TCP' -Direction Inbound -Protocol TCP -LocalPort {0} -Action Allow; New-NetFirewallRule -DisplayName 'Allow {0} UDP' -Direction Inbound -Protocol UDP -LocalPort {0} -Action Allow" -f $m)
    }
    if ($off.Count -gt 0) {
        $names = ($off | ForEach-Object { $_.Name }) -join ', '
        if ($missing.Count -eq 0) {
            if ($OfferFix -and (Ask "  Firewall is OFF for: $names. Allow rules for 53/88/389 exist. Turn it ON?")) {
                Set-NetFirewallProfile -All -Enabled True; Ok 'firewall on (check Hermes in 1 minute)'
            } else { Add-Flag 'CHECK' "Firewall is OFF for: $names" 'Set-NetFirewallProfile -All -Enabled True   (then check Hermes)' }
        } else { Add-Flag 'FLAG' "Firewall is OFF for: $names - fix the missing allow rules BEFORE turning it on" 'add the missing port rules above first (the New-NetFirewallRule fixes)' }
    } else { Ok 'all firewall profiles on' }
    $state = @()
    $custom = @(Get-NetFirewallRule -Enabled True -ErrorAction SilentlyContinue | Where-Object { [string]::IsNullOrEmpty($_.DisplayGroup) })
    foreach ($r in $custom) {
        $state += "$($r.DisplayName) [$($r.Direction) $($r.Action)]"
        if ($r.DisplayName -match $AgentRx) { continue }
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

function Check-GPOs {
    Section 'Group Policy objects'
    try { $gpos = @(Get-GPO -All -ErrorAction Stop) } catch { Info 'GroupPolicy module not available'; return }
    $state = @()
    $recent = (Get-Date).AddHours(-6)
    foreach ($g in ($gpos | Sort-Object ModificationTime -Descending)) {
        $state += "{0} | {1}" -f $g.DisplayName, $g.ModificationTime
        $isDefault = @('Default Domain Policy', 'Default Domain Controllers Policy') -contains $g.DisplayName
        $rep = "Get-GPOReport -Name '{0}' -ReportType Html -Path 'C:\Users\Public\bk\gpo_report.html'   (open it in a browser and read the settings)" -f $g.DisplayName
        if (-not $isDefault) { Add-Flag 'CHECK' ("Non-default GPO '{0}' (changed {1})" -f $g.DisplayName, $g.ModificationTime) $rep }
        elseif ($g.ModificationTime -gt $recent) { Add-Flag 'CHECK' ("Default GPO '{0}' changed recently ({1})" -f $g.DisplayName, $g.ModificationTime) $rep }
    }
    Ok ("{0} GPOs checked" -f $gpos.Count)
    Compare-State 'gpos' $state 'GPO (name | last changed)'
}

function Check-DnsRecords {
    Section 'DNS records'
    try {
        $cur = @(Get-DnsServerResourceRecord -ZoneName $Zone -RRType A -ErrorAction Stop |
            ForEach-Object { "{0}={1}" -f $_.HostName, $_.RecordData.IPv4Address.IPAddressToString })
    } catch { Add-Flag 'FLAG' "Could not read DNS zone $Zone" 'Get-DnsServerZone   (is the zone still there?)'; return }
    $bkFile = Join-Path $BK 'dns_A.csv'
    if (Test-Path $bkFile) {
        $orig = @(Import-Csv $bkFile)
        $origKeys = @($orig | ForEach-Object { "{0}={1}" -f $_.HostName, $_.IP })
        foreach ($r in $orig) {
            $key = "{0}={1}" -f $r.HostName, $r.IP
            if ($cur -notcontains $key) { Add-Flag 'FLAG' "DNS A record missing or changed: $($r.HostName) should be $($r.IP)" ("Add-DnsServerResourceRecordA -ZoneName '{0}' -Name '{1}' -IPv4Address '{2}'" -f $Zone, $r.HostName, $r.IP) }
        }
        foreach ($c in $cur) {
            if ($origKeys -notcontains $c) {
                $h = $c.Split('=')[0]; $ip = $c.Split('=')[1]
                Add-Flag 'CHECK' "DNS A record not in the backup: $c" ("Remove-DnsServerResourceRecord -ZoneName '{0}' -RRType A -Name '{1}' -RecordData '{2}' -Force   (only if it's bad)" -f $Zone, $h, $ip)
            }
        }
    } else { Write-Host '  No DNS backup yet. Run -Setup first.' -ForegroundColor Yellow }
    Ok ("{0} A records" -f $cur.Count)
}

function Show-Sessions {
    Section 'Who is logged in'
    try { $q = quser 2>$null; if ($q) { $q | ForEach-Object { Info $_ } } else { Info 'no sessions listed' } } catch { Info 'quser not available' }
}

function Run-Hunt {
    $script:Flags.Clear(); $script:NewItems = @(); $script:AccountIssues = 0; $script:FirstRun = $false
    Write-Host ''
    Write-Host ("pitwall hunt - {0} - {1}" -f $Zone, (Get-Date -Format 'HH:mm')) -ForegroundColor Cyan
    Check-Health; Check-Users; Check-PrivGroups; Check-Ports; Check-Connections; Check-Processes
    Check-Tasks; Check-Services; Check-Autostarts; Check-Firewall ([bool]$Setup); Check-Defender
    Check-Hosts; Check-GPOs; Check-DnsRecords; Show-Sessions

    Section 'CHANGED SINCE LAST HUNT'
    if ($script:FirstRun) { Info 'first hunt - saved a baseline. Next hunt shows what changed.' }
    elseif ($script:NewItems.Count -eq 0) { Ok 'nothing new' }
    else { foreach ($n in $script:NewItems) { Write-Host "  $n" -ForegroundColor Magenta } }

    Section 'TO DO  (FLAG = almost surely red team, CHECK = look at it, may be fine)'
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
    Write-Host 'pitwall.ps1 - IRSeC 2026 Team 10 domain controller helper'
    Write-Host '  -Setup  once at the start: backup, passwords, quick hardening, then a hunt'
    Write-Host '  -Hunt   every 10-15 min: read-only checks, what changed, fix commands'
    Write-Host '  powershell -ExecutionPolicy Bypass -File .\pitwall.ps1 -Setup'
    exit
}
if (-not $isAdmin) { Write-Host 'Run PowerShell as Administrator.' -ForegroundColor Red; exit 1 }

New-Item -ItemType Directory -Force -Path $BK, $script:StateDir | Out-Null
try { Import-Module ActiveDirectory -ErrorAction Stop } catch { Write-Host 'ActiveDirectory module missing - is this the DC?' -ForegroundColor Red; exit 1 }
Import-Module GroupPolicy -ErrorAction SilentlyContinue
Import-Module DnsServer -ErrorAction SilentlyContinue
$Zone = (Get-ADDomain).DNSRoot
$mode = 'hunt'; if ($Setup) { $mode = 'setup' }
$script:Log = Join-Path $BK ("{0}_{1}.txt" -f $mode, (Get-Date -Format 'MMdd_HHmm'))
Start-Transcript -Path $script:Log -Append | Out-Null

if ($Setup) {
    Write-Host ("pitwall setup - {0}" -f $Zone) -ForegroundColor Cyan
    Do-Backup

    Section 'Passwords'
    Write-Host '  First: Hermes > Checks. Note which accounts the AD and DNS checks log in with.' -ForegroundColor Yellow
    if (Ask '  Change passwords now?') {
        $adminPw = Read-NewPassword 'the 4 domain admins + Administrator'
        Set-Passwords ($PacketAdmins + @('Administrator')) $adminPw
        $userPw = Read-NewPassword 'the 6 regular users'
        Set-Passwords $PacketUsers $userPw
        Write-Host '  Put both passwords in the team password sheet NOW.' -ForegroundColor Yellow
        Write-Host '  If a Hermes check logs in with one of these accounts, update it in Hermes > Checks.' -ForegroundColor Yellow
    }

    Section 'Quick hardening'
    try { Disable-ADAccount -Identity 'Guest' -ErrorAction Stop; Ok 'Guest disabled' } catch { Info "Guest: $($_.Exception.Message)" }
    Enable-Logging
    try { Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction Stop; Ok 'SMBv1 off' } catch { Info "SMBv1: $($_.Exception.Message)" }

    Fix-Accounts
}

Run-Hunt
Stop-Transcript | Out-Null
