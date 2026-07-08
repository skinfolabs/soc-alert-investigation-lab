# Final Summary

This project demonstrates SOC triage across three different alert types: a FortiGate command-injection attempt, a QR-code phishing email, and a Microsoft Sentinel/Sysmon discovery incident. Each case is documented with an evidence-led structure so the reader can see what was observed, why it mattered, what was confirmed, and what remained unverified.

The FortiGate case confirms a malicious exploitation attempt with Mirai-related payload context, but compromise requires server-side proof. The QR case is likely false positive for confirmed phishing because controlled sandbox, VirtualBox, and PCAP evidence show an ad-supported Me-QR redirect that reaches legitimate Facebook/Meta infrastructure. The Sentinel/Sysmon case is true-positive suspicious endpoint activity built from `Gift.xlsm`, Excel-linked `whoami`, `file.io` downloads, MalwareBazaar-style transfer, domain-controller checks, and cleanup artifacts.

## Validation Summary

| Control or Area | Validation Captured |
|-----------------|---------------------|
| FortiGate command injection | FortiGate evidence confirms a malicious command-injection request and identifies the source, destination, payload host, HTTP service, user agent, and `Accept` action. |
| Payload and source enrichment | Reputation checks support the malicious classification of the command-injection infrastructure, including Mirai-related context. |
| QR redirect validation | QR, VirtualBox sandbox, and PCAP validation show an ad-supported Me-QR redirect that reaches legitimate Facebook/Meta infrastructure. |
| Sentinel/Sysmon telemetry | Sysmon Event ID 1 evidence confirms repeated `whoami.exe` executions, Excel parent-process context, `Gift.xlsm`, changed process IDs, downloads, internal checks, and cleanup-related behavior. |
| Evidence limits | Server compromise, QR sender authentication, macro code, payload execution, credential theft, persistence, and lateral movement are not fully proven by the available artifacts. |

## Production Recommendations

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

---

## Project Chapters

| # | Chapter | Description |
|---|---------|-------------|
| 0 | [Project Overview](../../README.md) | Main project overview, objectives, tools, and skills. |
| 1 | [FortiGate Command Injection](../01-fortigate-command-injection/README.md) | Inbound HTTP command-injection attempt, payload host enrichment, Mirai context, and server-side validation limits. |
| 2 | [Quishing Email Analysis](../02-quishing-email-analysis/README.md) | QR email triage, sender review, decoded destination, VirtualBox sandbox validation, and PCAP evidence. |
| 3 | [Sentinel Sysmon Discovery](../03-sentinel-sysmon-discovery/README.md) | Sentinel/Sysmon discovery activity, process timelines, downloads, and response guidance. |
| 4 | [Final Summary](README.md) | Final verdicts, validation summary, recommendations, skills, and remaining evidence limits. |
