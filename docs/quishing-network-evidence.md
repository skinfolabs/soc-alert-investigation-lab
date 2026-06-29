# Quishing Network Evidence

## QR Redirect Flow

The QR investigation used Any.Run/sandbox evidence and PCAP review to validate the destination reached after scanning the code. The alert was worth investigating because QR codes hide the destination from the user, and the first decoded URL used an intermediate QR redirect service.

| Stage | Evidence | Assessment |
|-------|----------|------------|
| Email lure | The message asks the recipient to scan a QR code and join a Facebook group. | Suspicious enough for triage because the destination is hidden until decoded. |
| Sender quality | The display name appears as `avi.waisman` instead of a normal full name. | Weak identity-quality signal; not enough to prove phishing. |
| Intermediate URL | `https://qr.me-qr.com/shP847fW` | Me-QR redirect service; can be legitimate but can also hide final destinations. |
| Any.Run/sandbox behavior | Me-QR page shows an ad-gated `Watch to continue` flow with a skip option. | Consistent with an ad-supported QR redirect service. |
| Final destination | `https://www.facebook.com/?locale=he_IL` | Legitimate Facebook domain, not a counterfeit Facebook login domain. |

## PCAP Indicators

The packet capture supports the same redirect story. DNS and TLS metadata show Me-QR, advertising/measurement infrastructure, and then Facebook/Meta infrastructure.

| Indicator | Role |
|-----------|------|
| `qr.me-qr.com` | Initial QR redirect domain. |
| `cdn.me-qr.com` | Me-QR supporting content/CDN domain. |
| `pagead2.googlesyndication.com`, `securepubads.g.doubleclick.net`, `googleads.g.doubleclick.net` | Advertising infrastructure consistent with the ad-gated redirect step. |
| `www.googletagmanager.com`, `www.google-analytics.com` | Measurement/analytics domains commonly loaded by web pages. |
| `www.facebook.com` | Final legitimate Facebook destination. |
| `static.xx.fbcdn.net`, `scontent.xx.fbcdn.net`, `video.xx.fbcdn.net` | Facebook content-delivery infrastructure. |
| `accounts.meta.com` | Meta account infrastructure observed after the redirect flow. |

## Analyst Conclusion

The evidence supports a false-positive disposition for confirmed phishing. The QR code is suspicious as a delivery mechanism, and the sender formatting should be reviewed, but the observed path does not show a fake login page, malware download, or credential-harvesting domain.

The remaining validation should focus on full email headers, sender confirmation, and mail-gateway click telemetry. A man-in-the-middle scenario is not supported by the current evidence because the observed network flow reaches expected Facebook and Meta infrastructure.
