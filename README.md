# SOC Alerts Investigation Lab

![Category](https://img.shields.io/badge/Category-SOC%20Investigation-blue)
![Platform](https://img.shields.io/badge/Platform-FortiGate%20%7C%20Microsoft%20Sentinel-lightgrey)
![Focus](https://img.shields.io/badge/Focus-Alert%20Triage%20%7C%20Quishing%20%7C%20Sysmon-blueviolet)
![Status](https://img.shields.io/badge/Status-Completed-brightgreen)

> Project by Samuel Kim. All rights reserved. See [LICENSE](LICENSE).

## Project Overview

This repository documents three evidence-led SOC investigations: a FortiGate command-injection alert, a QR-code phishing email, and a Microsoft Sentinel/Sysmon discovery incident. The project focuses on how an analyst moves from an initial alert to a defensible conclusion by separating confirmed evidence from assumptions, reviewing screenshots and logs in sequence, mapping behavior to MITRE ATT&CK, and documenting practical response actions.

The final results are mixed by design: the FortiGate case is a true-positive exploitation attempt without proof of server compromise, the QR phishing case is a likely false positive for confirmed phishing after sandbox and PCAP validation, and the Sentinel/Sysmon case is true-positive suspicious endpoint activity tied to Excel-launched discovery and file-transfer behavior.

## Objectives

- Review each alert and identify the strongest technical evidence.
- Sort the investigation into clear steps instead of leaving screenshots and notes scattered across one long report.
- Explain what each screenshot proves, what it does not prove, and which follow-up checks are required.
- Map confirmed behavior to Cyber Kill Chain stages and MITRE ATT&CK techniques.
- Produce a clean portfolio structure with a short landing page and detailed chapter READMEs.

## Project Chapters

| # | Chapter | Description |
|---|---------|-------------|
| 1 | [FortiGate Command Injection](docs/01-fortigate-command-injection/README.md) | Inbound HTTP command-injection attempt, payload host enrichment, Mirai context, and server-side validation limits. |
| 2 | [Quishing Email Analysis](docs/02-quishing-email-analysis/README.md) | QR email triage, sender review, decoded destination, VirtualBox sandbox validation, and PCAP evidence. |
| 3 | [Sentinel Sysmon Discovery](docs/03-sentinel-sysmon-discovery/README.md) | `New Discovery Command Detected`, Sysmon process telemetry, `whoami`, `Gift.xlsm`, downloads, and cleanup context. |
| 4 | [Final Summary](docs/04-final-summary/README.md) | Final verdicts, validation summary, recommendations, skills, and remaining evidence limits. |

## Investigation Results

| Case | Initial signal | Final assessment |
|------|----------------|------------------|
| FortiGate command injection | HTTP request with injected shell commands | True positive malicious exploitation attempt against `web.seesec.co.il`; compromise is not proven without server-side logs. |
| Quishing email | QR code inside an email message | Likely false positive for confirmed phishing: the QR flow uses Me-QR and reaches legitimate Facebook/Meta infrastructure, with sender-header validation still required. |
| Sentinel/Sysmon discovery | `whoami` activity in Sysmon logs | True-positive suspicious endpoint activity involving Sysmon Event ID 1, Excel-launched `whoami`, `Gift.xlsm`, file-transfer commands, domain-controller reachability checks, and cleanup-related artifacts. |

## Tools and Technologies

- FortiGate IPS
- Microsoft Sentinel
- Sysmon Event ID 1 process telemetry
- Kusto Query Language
- VirusTotal and AbuseIPDB enrichment
- Any.Run, VirtualBox sandbox validation, and PCAP review
- QR decoding and email inspection workflow
- MITRE ATT&CK and Cyber Kill Chain mapping

## Key Technical Terms

| Term | Meaning in this project |
|------|-------------------------|
| SOC triage | The process of reviewing an alert, validating evidence, and deciding whether it is malicious, benign, suspicious, or inconclusive. |
| SIEM | A platform that centralizes security logs and allows analysts to search, correlate, and investigate events. |
| Sysmon Event ID 1 | Windows process-creation telemetry that records process image, command line, parent process, user, and process IDs. |
| IOC | An indicator of compromise such as an IP address, domain, URL, file path, hash, command, or process chain. |
| PCAP | Packet capture evidence used to review network domains, connections, redirects, and traffic sequence. |
| Evidence limit | A point where the available artifact supports part of a conclusion but cannot prove the full attack outcome. |

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
