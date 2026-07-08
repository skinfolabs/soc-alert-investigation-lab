# Quishing Email Analysis

This chapter investigates a QR-code phishing alert. The email asks the recipient to scan a QR code and join a Facebook group, which hides the final destination until the code is decoded or opened safely. The investigation validates the QR behavior through sandbox analysis, an isolated VirtualBox virtual machine, and PCAP evidence.

## Technical Context

Quishing means QR-code phishing. Attackers use QR images to move users away from protected email tooling and into browsers or mobile devices where inspection can be weaker. A QR code is not malicious by itself, so the analyst must validate the sender, decoded URL, redirect path, final destination, and network traffic.

> The suspicious delivery method justified triage. The validated evidence does not support confirmed credential phishing because the observed redirect flow reaches legitimate Facebook/Meta infrastructure instead of a counterfeit login domain.

**Implemented controls and analysis actions:**

- Reviewed the email lure and visible sender/recipient details.
- Checked sender identity quality and documented missing header validation.
- Decoded the QR URL and reviewed vendor detections.
- Opened the decoded QR link in a controlled VirtualBox sandbox, not on the analyst host.
- Compared sandbox behavior with PCAP domains.
- Documented the false-positive disposition and remaining validation requirements.

## Key Technical Terms

| Term | Meaning in this chapter |
|------|-------------------------|
| Quishing | Phishing that uses a QR code to hide or redirect the destination. |
| QR redirector | A service that receives the QR scan and redirects the browser to another destination. |
| Sender validation | Review of sender address, display name, and email authentication such as SPF, DKIM, and DMARC. |
| Sandbox | An isolated environment used to open suspicious content without exposing the analyst workstation. |
| PCAP | Network capture evidence used to confirm which domains were contacted during the redirect flow. |

---

## Detailed Walkthrough

### Step 01 - Review the email lure

The email asks the user to scan a QR code and join a Facebook group. This can be legitimate or malicious, so the first step is to treat the QR code as an unknown destination and decode it before judgment.

> A screenshot of an email lure proves delivery content, not phishing success. It does not prove a fake login page, credential theft, attachment execution, or malware download.

![Suspicious email with QR code](../../images/02-quishing/email-message-with-qr-code.png)

<p><sub><strong>Screenshot 010 - Suspicious email with QR code:</strong> The email contains sender and recipient details plus a QR code that asks the user to follow an external path.</sub></p>

The screenshot shows the delivery object only. It does not show a fake login page, attachment, malware download, or credential prompt.

---

### Step 02 - Validate the sender identity

The sender address is `avi.waisman@see-security.com`, but the display name appears as `avi.waisman` instead of a clean personal name. The sender and recipient domains, `see-security.com` and `see-secure.com`, are similar enough to review, although `see-security.com` is known in this lab context.

> Mailbox validation is a weak signal. A result can be affected by catch-all domains, anti-enumeration, temporary server behavior, or mail-provider controls.

![Sender mailbox validation result](../../images/02-quishing/email-address-undeliverable-check.png)

<p><sub><strong>Screenshot 011 - Sender mailbox validation result:</strong> The mailbox check marks `avi.waisman@see-security.com` as undeliverable, which supports additional caution but does not prove spoofing by itself.</sub></p>

Full email headers are not available, so SPF, DKIM, DMARC, and Received-path validation cannot be completed. A man-in-the-middle scenario is not supported by the current evidence; the stronger explanation is a legitimate QR redirect flow with weak sender-formatting signals.

---

### Step 03 - Decode and inspect the QR destination

The QR code resolves to `https://qr.me-qr.com/shP847fW`, an intermediate QR redirect service. Redirectors can hide final destinations, which makes the alert plausible even when the final page may be legitimate.

> URL reputation is useful for triage, but the key question is where this specific QR link led during controlled testing.

![Security vendor detections for QR URL](../../images/02-quishing/qr-url-vendor-detections.png)

<p><sub><strong>Screenshot 012 - Security vendor detections for QR URL:</strong> The decoded QR URL is checked against security vendors and receives malicious or suspicious detections.</sub></p>

The reputation result supports caution, but it does not prove that this QR instance performed credential harvesting or payload delivery.

---

### Step 04 - Validate QR behavior in VirtualBox sandbox and PCAP evidence

The decoded QR link was opened only in a controlled lab environment, not on the analyst host. The URL was validated through sandbox analysis and by manually opening it inside an isolated VirtualBox virtual machine so browser behavior and network traffic could be observed safely.

> Opening suspicious links inside an isolated environment reduces analyst risk and allows the redirect path, browser behavior, and network traffic to be reviewed without trusting the destination.

![Me-QR ad gate after QR scan](../../images/02-quishing/meqr-ad-gate-after-qr-scan.png)

<p><sub><strong>Screenshot 013 - Me-QR ad gate after QR scan:</strong> The QR link opens an intermediate Me-QR page that requires watching or skipping an ad before continuing.</sub></p>

The page looks suspicious because it hides the final destination behind an advertisement flow. For this case, however, the screenshot shows ad-gated redirection rather than confirmed credential phishing.

![Facebook final destination](../../images/02-quishing/facebook-login-final-destination.png)

<p><sub><strong>Screenshot 014 - Facebook final destination:</strong> The redirect flow reaches the legitimate `www.facebook.com` login page using the Hebrew locale.</sub></p>

The page is still a login page, so the domain matters. Here it reaches `www.facebook.com`, not a lookalike or non-Meta host.

| Observed domain group | Meaning in the investigation |
|-----------------------|------------------------------|
| `qr.me-qr.com` / `cdn.me-qr.com` | Intermediate QR redirect and content-delivery infrastructure. |
| Google ad and measurement domains | Consistent with the ad-gated Me-QR page shown in the sandbox. |
| `www.facebook.com`, `fbcdn.net`, `accounts.meta.com` | Legitimate Facebook/Meta infrastructure reached after the redirect flow. |

The PCAP supports the same conclusion: Me-QR and Google ad/measurement domains appear first, followed by Facebook/Meta infrastructure. No counterfeit Facebook domain or malware download is visible. A compact domain summary is documented in [quishing-network-evidence.md](../quishing-network-evidence.md).

---

### Step 05 - Define response and closure actions

The response should preserve the email, collect full headers, confirm the campaign with the sender or organization, and monitor the QR URL for destination changes. If authentication fails or the destination changes to credential harvesting, the case should be reopened as phishing.

> The correct finding is suspicious QR delivery, not confirmed credential theft. The available evidence shows an ad-gated QR redirect flow that resolves to a legitimate Facebook destination.

| Field | Assessment |
|-------|------------|
| Verdict | False positive for confirmed phishing; suspicious QR delivery still justified triage. |
| Attack status | No confirmed attack. The controlled flow shows an ad-supported Me-QR redirect that reaches legitimate Facebook/Meta infrastructure. |
| Key evidence | QR delivery, weak sender display-name formatting, `qr.me-qr.com` redirect, controlled VirtualBox opening, Me-QR ad gate, final `www.facebook.com` destination, and PCAP domains matching QR, ad, Facebook, and Meta infrastructure. |
| Kill Chain and MITRE | Initially triaged as Delivery. [T1566.002 - Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/) and [T1204 - User Execution](https://attack.mitre.org/techniques/T1204/) are considered but not confirmed as malicious techniques. |
| Evidence limits | Full email headers are unavailable; SPF, DKIM, DMARC, Received path, QR owner, and sender intent still require validation. |
| Next checks | Collect headers, confirm the campaign with the sender or organization, review mail-gateway click telemetry, check other recipients, and monitor the QR URL for destination changes. |
| Recommendation | Close as false positive if sender confirmation and authentication are clean; keep QR redirect monitoring separate from confirmed credential-harvesting alerts. |

This case shows why QR phishing alerts should be validated safely: the delivery method was suspicious, but the observed path did not show credential harvesting or payload delivery.

---

## Validation and Summary

QR, VirtualBox sandbox, and PCAP validation show an ad-supported Me-QR redirect that reaches legitimate Facebook/Meta infrastructure. The case remains useful as a triage example because it separates suspicious delivery from confirmed malicious outcome.

---

## Project Chapters

| # | Chapter | Description |
|---|---------|-------------|
| 0 | [Project Overview](../../README.md) | Main project overview, objectives, tools, and skills. |
| 1 | [FortiGate Command Injection](../01-fortigate-command-injection/README.md) | Inbound HTTP command-injection attempt, payload host enrichment, Mirai context, and server-side validation limits. |
| 2 | [Quishing Email Analysis](README.md) | QR email triage, sender review, decoded destination, VirtualBox sandbox validation, and PCAP evidence. |
| 3 | [Sentinel Sysmon Discovery](../03-sentinel-sysmon-discovery/README.md) | Sentinel/Sysmon discovery activity, process timelines, downloads, and response guidance. |
| 4 | [Final Summary](../04-final-summary/README.md) | Final verdicts, validation summary, recommendations, skills, and remaining evidence limits. |
