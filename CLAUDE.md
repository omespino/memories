# Global Claude Code Instructions

These memories must be loaded in every Claude Code session, regardless of the working directory.

## User Profile and Rules

@/Users/user/.claude/memory/user_profile.md

@/Users/user/.claude/memory/feedback_language_style.md

@/Users/user/.claude/memory/feedback_no_auto_requests.md

@/Users/user/.claude/memory/feedback_use_ripgrep.md

## Engagement Rules

@/Users/user/.claude/memory/reference_bugbounty_rules.md

@/Users/user/.claude/memory/reference_pentest_rules.md

@/Users/user/.claude/memory/reference_rdoc_review.md

## Skills (auto-discovered, loaded on-demand)

The following skills live in `~/.claude/skills/`. Most are `user-invocable-only` (require explicit invocation); only `pentest-skills` auto-loads based on context. Do NOT @-import them here — that would defeat the on-demand loading.

- `shodan-recon` — Shodan CLI/REST/InternetDB recon, filter syntax, credit costs, network alerts. Triggers on Shodan, passive recon, asset discovery, vulnerable-service hunting.
- `pentest-skills` — Real pentest techniques from ~25 engagements: AD (Kerberoasting, SMB relay, LLMNR poisoning), credential exposure, IDOR/BOLA, business logic, mobile, CVEs, weak crypto, unauthenticated services, web app findings, physical pentest. Triggers on authorized pentest/auditoría engagements.
- `h1-bugbounty` — HackerOne techniques from 43 reports (9 resolved): SVG/XML XSS on iOS, ASCII homoglyph bypass, SSRF in webhooks, Heroku subdomain takeover, GitHub recon, CVE-2018-0296 Cisco ASA, CVE-2019-11510 Pulse Secure, SSL legacy. Triggers on HackerOne / H1 / Live Hacking Events.
- `bugcrowd-bugbounty` — BugCrowd techniques: XSS via .doc/.svg on iOS, CVE-2018-0296 Cisco ASA, Firebase APK recon, default creds on network gear, email domain spoofing on SaaS, API keys in APK assets/. Triggers on BugCrowd programs.
- `google-bughunters-cloud` — Personal Google VRP reports by omespino (cloud/infra): Cloud Shell instance takeover (XSS+LFI+container escape+SSH root), Apigee Node.js RCE as root, SSRF oracle via Uptime Check (0.0.0.0 + redirect to [::169.254.169.254]), SSRF AMP Validator → GCP metadata, LFI on Google prod servers via /procz (DremelGateway, springboard.google.com, UPI India, Mobile Harness), /labelaclz /flagz /streamz debug endpoints on 34.x/35.x/100.x/108.x ASN, Google Fiber FTP/Telnet. Triggers on Cloud Shell, Apigee, procz/flagz, SSRF GCP, springboard, debug endpoints Google.
- `google-bughunters-mobile` — Personal Google VRP reports by omespino (mobile/desktop): Gmail Android content:// URI email leak, Google Earth iOS KML geolocation XSS, Google Earth Pro Linux KML LFI, Google Earth Pro macOS null byte bypass, Chrome file:///etc/environment as JS, Android TV IDOR enumeration, PowerPoint 97-2003 XSS in Gmail iOS / Drive iOS. Triggers on Gmail Android, Google Earth KML, Earth iOS, file:// Chrome, Android TV IDOR, PowerPoint XSS iOS.
- `google-vrp-cloud` — GCP Classic App LB/CDN HTTP parser quirks, GitHub Actions pwn requests, GCS bucket squatting, GKE WIF downgrade, Zip Slip RCE, GAR plugin bypass, Firebase SA key leak, Apigee sandbox escapes, Composer/Airflow RCE, Cloud Shell root, Cloud VRP / OSS VRP. Triggers on GCP, Cloud Shell, GKE, Apigee, Firebase backend, GitHub Actions Google, OSS VRP.
- `google-vrp-web` — Web app XSS, OAuth misconfigs, SSRF, IDOR in Google web services (Drive, Docs, Gmail, YouTube, Workspace, Kaggle, Fitbit, VirusTotal). postMessage targetOrigin bypass, Golang net/html XSS, auth-flow helper pages, HTML upload endpoints. Triggers on Google web app XSS, OAuth Google, Drive/Docs/Gmail, IDOR Google.
- `google-vrp-android` — Android intent redirects (BROWSABLE bypass), path traversal in attachments, confused-deputy cross-user content://, Chrome extension UXSS, Tag Assistant SOP bypass, Google App fullscreen spoof, kernelCTF/v8CTF exploits, Fuchsia/gVisor PRNG leak. Triggers on Android Google, Mobile VRP, Chrome extension, kernelCTF.

## Memory Index

@/Users/user/.claude/memory/MEMORY.md
