# Memory Index

- [Spanish without regional accent](feedback_language_style.md) — Use neutral Spanish, never Argentinian/voseo or other regional dialects.
- [Ripgrep/grep usage and pre-authorization](feedback_use_ripgrep.md) — prefer `rg` over `grep`; both are pre-authorized, never ask for confirmation.
- [rdoc — Document Review Command](reference_rdoc_review.md) — When invoking /rdoc with a PDF: review style, spelling, coherence, single client (cover), WebSec vendor, CVSS and overall quality. Reports are in Spanish by default unless the user indicates otherwise.
- [User Profile](user_profile.md) — Pentester and bug bounty hunter with advanced experience in offensive security.
- [Bug Bounty Rules](reference_bugbounty_rules.md) — Authorized by the target's public program; pursue maximum critical impact; PoCs 100% verifiable, nothing theoretical.
- [Pentest Rules](reference_pentest_rules.md) — Comprehensive vision: valid theoretical findings, outdated versions, OWASP Top 10, CVSS v3.1, standard tools (Nessus, Burp, SQLMap, Nuclei, FFUF, etc.).
- [Pentest Skills — Real Engagements](reference_pentest_skills.md) — Skills extracted from ~25 real reports (2023-2026): Kerberoasting, SMB relay, IDOR, business logic, mobile, CVEs, physical pentest, web app.
- [No automatic HTTP/network requests](feedback_no_auto_requests.md) — Never execute requests automatically; present theoretical scenarios and only execute what the user explicitly approves.
- [HackerOne Bug Bounty Skills](reference_h1_skills.md) — Real skills from 43 H1 reports (9 resolved): SVG/XML XSS on iOS, ASCII homoglyph bypass, SSRF in webhooks, Heroku subdomain takeover, GitHub recon, CVE exploitation, SSL legacy detection.
- [BugCrowd Bug Bounty Skills](reference_bugcrowd_skills.md) — Real skills from BugCrowd reports: XSS via .doc/.svg on iOS, CVE-2018-0296 Cisco ASA, Firebase APK recon, default creds on network gear, email domain spoofing on SaaS.
- [Shodan Reconnaissance](reference_shodan_recon.md) — CLI / REST / InternetDB / alert workflows, filter syntax, credit costs, paid vs free features. Active scans require explicit user confirmation per `feedback_no_auto_requests.md`.

## On-demand (NOT auto-loaded — load with Read only when context requires it)
- [Google Bug Hunters Skills](reference_bughunters_skills.md) — **ON-DEMAND.** omespino's Google VRP reports (Cloud Shell root takeover, internal Google IP LFI, etc.). Load when target is Google / Google Cloud.
- [Google VRP Public Hall-of-Fame Skills](reference_google_vrp_public_hof.md) — **ON-DEMAND.** 202 public Google VRP / Cloud VRP / OSS VRP / Mobile VRP reports catalog. Load when hunting Google products.
