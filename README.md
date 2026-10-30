# irsec-pitwall

PowerShell helper for IRSeC 2026, Blue Team 10, box **pitwall** (domain controller: Active Directory + DNS).

## Usage

Run PowerShell as administrator on pitwall:

```powershell
powershell -ExecutionPolicy Bypass -File .\pitwall.ps1 -Setup   # once, at the start
powershell -ExecutionPolicy Bypass -File .\pitwall.ps1 -Hunt    # every 10-15 minutes
```

## What -Setup changes

- Backs up users, GPOs, DNS records/zone, firewall rules, services, and scheduled tasks to `C:\Users\Public\bk`
- Resets passwords for the packet's domain users + Administrator (operator types the new passwords; asks first)
- Disables the Guest account
- Turns on audit logging, PowerShell script block logging, and process command-line logging
- Turns off SMBv1
- Asks y/n before removing each non-packet member of an admin group, and before disabling each unknown user
- Asks y/n before turning the firewall on, and only offers it if inbound allow rules for 53/88/389 exist

## What -Hunt does

Read-only. Compares the box to the packet and to a normal domain controller (users, admin groups, listening ports, outside connections, processes, scheduled tasks, services, Run keys, Winlogon, IFEO, startup folders, firewall rules, Defender exclusions, hosts file, GPOs, DNS records), shows what changed since the last hunt, and prints a suggested fix command for each finding. It changes nothing unless the operator answers y to the account-fix prompt. Output is saved to `C:\Users\Public\bk`.

## Never touches

whiteteam, krbtgt, dd-agent, ddagentuser, DataDog, Wazuh, Defender settings. Never deletes users. Never scans files or sends anything off the box.
