# irsec-pitwall

PowerShell helpers for IRSeC 2026, Blue Team 10.

| Script | Box | Scored services |
| --- | --- | --- |
| `pitwall.ps1` | pitwall (domain controller) | Active Directory, DNS |
| `safetycar.ps1` | safetycar, also teamradio | ICMP + Telnet (safetycar), WinRM (teamradio) |

## Usage

Run PowerShell as administrator on the box:

```powershell
powershell -ExecutionPolicy Bypass -File .\pitwall.ps1 -Setup     # once, at the start
powershell -ExecutionPolicy Bypass -File .\pitwall.ps1 -Hunt      # every 10-15 minutes

powershell -ExecutionPolicy Bypass -File .\safetycar.ps1 -Setup
powershell -ExecutionPolicy Bypass -File .\safetycar.ps1 -Hunt
```

`safetycar.ps1` picks its scored-service checks from the computer name. Override with `-Box safetycar` or `-Box teamradio`.

## What -Setup changes

Both scripts:

- Back up users, groups, firewall rules, services, and scheduled tasks to `C:\Users\Public\bk` (pitwall.ps1 also backs up GPOs and DNS records/zone)
- Reset passwords for the packet's users (operator types the new passwords; asks first). pitwall.ps1: domain users + Administrator. safetycar.ps1: local users + Administrator.
- Disable the Guest account
- Turn on audit logging, PowerShell script block logging, and process command-line logging
- Turn off SMBv1
- Ask y/n before removing each non-packet member of an admin group, and before disabling each unknown user
- Ask y/n before turning the firewall on, and only offer it when allow rules exist for the box's scored services (pitwall: 53/88/389; safetycar: ICMP + 23; teamradio: 5985)

## What -Hunt does

Read-only. Checks that the scored services are up and allowed through the firewall, then compares the box to the packet and to a normal Windows install (users, admin groups, listening ports, outside connections, processes, scheduled tasks, services, Run keys, Winlogon, IFEO, startup folders, firewall rules, Defender exclusions, hosts file; pitwall.ps1 also checks GPOs and DNS records). Shows what changed since the last hunt and prints a suggested fix command for each finding. Changes nothing unless the operator answers y to the account-fix prompt. Output is saved to `C:\Users\Public\bk`.

## Never touches

whiteteam, 10.X.1.99 (NetBird egress), krbtgt, dd-agent, ddagentuser, DataDog, Wazuh, Defender settings, and the scored Telnet service itself. Never deletes users. Never scans files or sends anything off the box.
