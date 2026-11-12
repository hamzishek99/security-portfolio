# Detecting Common Windows Privilege Escalation Techniques with Wazuh

## Summary

Privilege escalation is how a threat actor turns a standard user foothold into administrator or NT AUTHORITY\SYSTEM control. On Windows it rarely needs an exploit. Actors achieve it by abusing the platform itself:

- **Service misconfiguration:** an unquoted service path, or a service registry key a standard user can write to.
- **Installer policy abuse:** the AlwaysInstallElevated policy, which lets any user run MSI packages as SYSTEM through msiexec.exe.
- **DLL search-order hijacking:** planting a DLL where a more privileged application will load it.
- **Scheduled task abuse:** replacing the binary a SYSTEM task executes with one the user controls.

I ran all five variants on a Windows endpoint in my lab, monitored with the same Wazuh setup as my other detection work. The detection side rests on Sysmon, which the Wazuh agent forwards to the server. Three Sysmon event IDs did most of the work in this exercise:

- **Event ID 13 (registry value set):** catches service ImagePath changes and installer policy changes the moment they are written.
- **Event ID 11 (file created):** catches a DLL being staged in a user-writable directory.
- **Event ID 7 (image loaded):** shows a SYSTEM process executing from a non-standard directory, the outcome of task or service abuse.

| # | Technique | ATT&CK | Sysmon event | Wazuh rule |
|---|---|---|---|---|
| 1 | Unquoted service path | T1574.009 | 13 | 111010 |
| 2 | Services registry permissions weakness | T1574.011 | 13 | 111020 |
| 3 | AlwaysInstallElevated through Msiexec | T1218.007 | 13 | 111030, 111031 |
| 4 | DLL search-order hijacking | T1574.001 | 11 | 111040 |
| 5 | Scheduled task binary replacement | T1053.005 | 7 | 111050 |

## 1. Unquoted service path (T1574.009)

When a service ImagePath contains spaces and no quotes, Windows tries each path segment in order. A service pointing at C:\Tools\Vulnerable Path\svc.exe can be intercepted by a binary placed at C:\Tools\Vulnerable.exe, and it runs with the service account's privileges.

I created a standard user with modify rights on C:\Tools, registered a service with an unquoted path, then, as the standard user, planted the intercepting binary and started the service:

```
> sc.exe create VulnUpdater binPath= "C:\Tools\Vulnerable Path\svc.exe" start= demand
> Copy-Item "C:\Windows\System32\cmd.exe" "C:\Tools\Vulnerable.exe"
> sc.exe start VulnUpdater
```

Rule 111010 (level 10) detects the misconfiguration itself: a Sysmon Event ID 13 writing a service ImagePath whose value is an unquoted path containing a space. The alert names the service and the exact path, so the weakness is visible before anyone exploits it.

![](images/unquoted-service-path-alert.png)

## 2. Services registry permissions weakness (T1574.011)

Service configuration lives under HKLM\SYSTEM\CurrentControlSet\Services. If a standard user can write to a service's key, the user can rewrite ImagePath and have the service execute their binary at next start.

I granted the standard user full control of a test service's key, then changed its ImagePath from the standard user session:

```
> Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WeakPermSvc" -Name ImagePath -Value "C:\Tools\AccessChk\accesschk64.exe -x"
```

Rule 111020 (level 12) keys on who made the change. Legitimate changes come from services.exe, the Service Control Manager. The rule alerts on a Sysmon Event ID 13 that modifies ImagePath, FailureCommand, or ServiceDll from any other process. In my run it showed PowerShell, the target value, and the user, which is the finding on its own.

![](images/service-registry-permissions-alert.png)

## 3. AlwaysInstallElevated through Msiexec (T1218.007)

AlwaysInstallElevated is a Windows Installer policy set by registry values under both HKLM and HKCU. With both set to 1, any user can install an MSI package with SYSTEM privileges, which makes a malicious MSI a direct escalation path.

I set the value in the machine hive, then in the standard user's hive:

```
> Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated -Value 1 -Type DWord
> Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated -Value 1 -Type DWord
```

Rule 111030 (level 12) fires on the Sysmon Event ID 13 that sets either value to 1. Rule 111031 (level 14) correlates: when 111030 matches two different registry locations within 10 minutes, both halves of the policy are set and the escalation actually works. One value is a note, both values are a SYSTEM path, and the severity reflects that.

![](images/always-install-elevated-alert.png)

## 4. DLL search-order hijacking (T1574.001)

When an application loads a DLL by name, Windows walks a search order of directories. A writable directory early in that order lets a standard user plant a DLL that a privileged application will load and execute.

I compiled a loader that loads somelibrary.dll by name, then, as the standard user, compiled a decoy DLL into C:\Tools and ran the loader. It loaded my DLL from C:\Tools.

```
> Add-Type -TypeDefinition $dllSource -OutputAssembly "C:\Tools\somelibrary.dll" -OutputType Library
> C:\Tools\DllLoadTest.exe
```

Rule 111040 (level 10) detects the preparation: a Sysmon Event ID 11 recording a DLL created outside the standard system and application directories. Catching the staging matters, because once a privileged application loads the DLL, the execution itself can look legitimate.

![](images/dll-hijacking-alert.png)

## 5. Scheduled task binary replacement (T1053.005)

A task running as SYSTEM is only as safe as the binary it points to. If that binary sits in a user-writable directory, the standard user replaces it and the task runs the replacement as SYSTEM.

I created a SYSTEM task running C:\Tools\maint.exe, granted the standard user modify rights on C:\Tools, then, as that user, swapped the binary and triggered the task:

```
> Remove-Item "C:\Tools\maint.exe" -Force
> Add-Type -TypeDefinition $hijackSource -OutputAssembly "C:\Tools\maint.exe" -OutputType ConsoleApplication
> schtasks.exe /run /tn "SystemMaintenance"
```

Rule 111050 (level 12) detects the outcome: a Sysmon Event ID 7 showing NT AUTHORITY\SYSTEM executing an image from outside the standard directories. A SYSTEM process running out of C:\Tools is almost never legitimate, and because the rule keys on the outcome, it catches the same weak-permission pattern reached through a service as well.

![](images/scheduled-task-system-alert.png)

## Results

All five techniques alerted in the dashboard, searchable in Threat Hunting by rule ID. The pattern across them: Sysmon Event ID 13 caught the registry-based techniques as the change was written, Event ID 11 caught the DLL staging, and Event ID 7 caught the SYSTEM execution at the end of the chain.

Three points are worth keeping:

- Privilege escalation on Windows is mostly misconfiguration, and misconfigurations are written to the registry and file system before they are abused, which is where Sysmon sees them first.
- The strongest detections key on who made the change. services.exe rewriting a service value is administration; PowerShell doing it from a standard user session is an incident.
- Correlation turns a policy change into a confirmed escalation path, as the AlwaysInstallElevated rule pair shows.

Hardening follows the same list: quote service ImagePaths, keep service registry keys and task binaries out of standard user write access, leave AlwaysInstallElevated unset, and keep application DLLs in protected directories.
