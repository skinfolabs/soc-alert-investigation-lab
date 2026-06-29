# Image Manifest

| Screenshot | Used in Report | Image | Description |
|------------|----------------|-------|-------------|
| Screenshot 001 | Yes | [`images/01-command-injection/fortigate-source-destination-summary.png`](images/01-command-injection/fortigate-source-destination-summary.png) | FortiGate log summary showing source and destination fields. |
| Screenshot 002 | Yes | [`images/01-command-injection/injected-luci-request-url.png`](images/01-command-injection/injected-luci-request-url.png) | Injected LuCI request URL containing shell commands and payload retrieval. |
| Screenshot 003 | Yes | [`images/01-command-injection/fortigate-ips-action-and-service.png`](images/01-command-injection/fortigate-ips-action-and-service.png) | FortiGate IPS fields showing Accept action, HTTP service, transfer size, and user agent. |
| Screenshot 004 | Yes | [`images/01-command-injection/abuseipdb-source-ip-profile.png`](images/01-command-injection/abuseipdb-source-ip-profile.png) | AbuseIPDB source IP profile for `195.1.144.109`. |
| Screenshot 005 | Yes | [`images/01-command-injection/source-ip-community-reports.png`](images/01-command-injection/source-ip-community-reports.png) | Community reports associating `195.1.144.109` with web exploit activity and TP-Link-focused probing. |
| Screenshot 006 | Yes | [`images/01-command-injection/virustotal-payload-ip-detection.png`](images/01-command-injection/virustotal-payload-ip-detection.png) | VirusTotal detection result for payload host `103.14.226.142`. |
| Screenshot 007 | Yes | [`images/01-command-injection/mirai-botnet-ioc-context.png`](images/01-command-injection/mirai-botnet-ioc-context.png) | Mirai Botnet IOC report listing `103.14.226.142`. |
| Screenshot 008 | Yes | [`images/01-command-injection/mirai-threat-description.png`](images/01-command-injection/mirai-threat-description.png) | Mirai IoT botnet description and capabilities. |
| Screenshot 009 | Yes | [`images/01-command-injection/mitre-t1059-command-interpreter.png`](images/01-command-injection/mitre-t1059-command-interpreter.png) | MITRE ATT&CK T1059 command interpreter reference screenshot. |
| Screenshot 010 | Yes | [`images/02-quishing/email-message-with-qr-code.png`](images/02-quishing/email-message-with-qr-code.png) | Suspicious email containing sender details, recipient details, and QR code. |
| Screenshot 011 | Yes | [`images/02-quishing/email-address-undeliverable-check.png`](images/02-quishing/email-address-undeliverable-check.png) | Email validation result showing the sender mailbox as undeliverable. |
| Screenshot 012 | Yes | [`images/02-quishing/qr-url-vendor-detections.png`](images/02-quishing/qr-url-vendor-detections.png) | Security vendor detections for the decoded QR URL. |
| Screenshot 013 | Yes | [`images/02-quishing/meqr-ad-gate-after-qr-scan.png`](images/02-quishing/meqr-ad-gate-after-qr-scan.png) | Me-QR intermediate page showing the ad-gated QR redirect flow. |
| Screenshot 014 | Yes | [`images/02-quishing/facebook-login-final-destination.png`](images/02-quishing/facebook-login-final-destination.png) | Final observed destination on legitimate `www.facebook.com`. |
| Screenshot 015 | Yes | [`images/03-sentinel-sysmon/sentinel-kql-whoami-results.png`](images/03-sentinel-sysmon/sentinel-kql-whoami-results.png) | Sentinel KQL query returning Sysmon events that contain `whoami`. |
| Screenshot 016 | Yes | [`images/03-sentinel-sysmon/changing-whoami-process-ids.png`](images/03-sentinel-sysmon/changing-whoami-process-ids.png) | Changing process IDs across repeated `whoami` executions. |
| Screenshot 017 | Yes | [`images/03-sentinel-sysmon/excel-parent-process-and-event-times.png`](images/03-sentinel-sysmon/excel-parent-process-and-event-times.png) | Excel parent process evidence and close-together `whoami` timestamps. |
| Screenshot 018 | Yes | [`images/03-sentinel-sysmon/whoami-event-time-sequence.png`](images/03-sentinel-sysmon/whoami-event-time-sequence.png) | Timestamp sequence for repeated `whoami` executions. |
| Screenshot 019 | Yes | [`images/03-sentinel-sysmon/elevated-command-context.png`](images/03-sentinel-sysmon/elevated-command-context.png) | Command line evidence showing an elevated context. |
| Screenshot 020 | Yes | [`images/03-sentinel-sysmon/onedrive-update-command.png`](images/03-sentinel-sysmon/onedrive-update-command.png) | Command line evidence referencing a OneDrive update path. |
| Screenshot 021 | Yes | [`images/03-sentinel-sysmon/cleanmgr-autoclean-command.png`](images/03-sentinel-sysmon/cleanmgr-autoclean-command.png) | Cleanmgr autoclean command evidence. |
| Screenshot 022 | Yes | [`images/03-sentinel-sysmon/ccleaner-and-office-processes.png`](images/03-sentinel-sysmon/ccleaner-and-office-processes.png) | Process list containing CCleaner and Microsoft Office activity. |
| Screenshot 023 | Yes | [`images/03-sentinel-sysmon/recon-and-process-timeline.png`](images/03-sentinel-sysmon/recon-and-process-timeline.png) | Timeline showing discovery commands, network checks, and related process activity. |
| Screenshot 024 | Yes | [`images/03-sentinel-sysmon/curl-download-and-ping-activity.png`](images/03-sentinel-sysmon/curl-download-and-ping-activity.png) | Command evidence showing ping activity and curl download behavior. |
| Screenshot 025 | Yes | [`images/03-sentinel-sysmon/virustotal-bazaar-abuse-domain-detection.png`](images/03-sentinel-sysmon/virustotal-bazaar-abuse-domain-detection.png) | VirusTotal domain detection context for `bazaar.abuse.ch`. |
| Screenshot 026 | Yes | [`images/03-sentinel-sysmon/repeated-gift-xlsm-downloads.png`](images/03-sentinel-sysmon/repeated-gift-xlsm-downloads.png) | Repeated `curl` downloads associated with `Gift.xlsm`. |
| Screenshot 027 | Yes | [`images/03-sentinel-sysmon/virustotal-file-io-community-context.png`](images/03-sentinel-sysmon/virustotal-file-io-community-context.png) | VirusTotal community context for `file.io` as a legitimate service that can be abused for payload hosting or downloader behavior. |
| Screenshot 028 | Yes | [`images/03-sentinel-sysmon/gift-xlsm-excel-execution-timeline.png`](images/03-sentinel-sysmon/gift-xlsm-excel-execution-timeline.png) | Excel execution timeline involving `Gift.xlsm`. |
| Screenshot 029 | Yes | [`images/03-sentinel-sysmon/extended-gift-xlsm-timeline.png`](images/03-sentinel-sysmon/extended-gift-xlsm-timeline.png) | Extended timeline around `Gift.xlsm` and related process activity. |
| Screenshot 030 | Yes | [`images/03-sentinel-sysmon/combined-whoami-gift-timeline.png`](images/03-sentinel-sysmon/combined-whoami-gift-timeline.png) | Combined timeline linking `whoami`, Excel, `Gift.xlsm`, and later commands. |
| Screenshot 031 | Supplementary | [`images/99-source-context/event-1-question-sheet.png`](images/99-source-context/event-1-question-sheet.png) | Event 1 question sheet preserved as supplementary context. |
| Screenshot 032 | Supplementary | [`images/99-source-context/event-2-question-sheet.png`](images/99-source-context/event-2-question-sheet.png) | Event 2 question sheet preserved as supplementary context. |
| Screenshot 033 | Supplementary | [`images/99-source-context/event-3-question-sheet.png`](images/99-source-context/event-3-question-sheet.png) | Event 3 question sheet preserved as supplementary context. |
