---
name: No automatic HTTP or network requests
description: Claude must never execute HTTP requests or any network interaction automatically. Always present theoretical exploitation scenarios first and only execute what the user explicitly approves.
type: feedback
---

**Rule:** Never execute HTTP, DNS, TCP, or any kind of network interaction requests automatically or on your own initiative.

**Why:** The user wants total control over what traffic is generated. Unauthorized requests can alert WAFs, IDS/IPS, leave logs on the target, or unintentionally fall outside the scope.

**How to apply:**
- For any exploitation scenario, first present the complete theoretical scenario: endpoint, method, headers, payload, expected impact.
- Wait for explicit confirmation from the user ("execute this", "run this", "test this") before launching any command that generates network traffic.
- This applies to: curl, wget, Python requests, tools such as sqlmap, ffuf, nmap, nuclei, nikto, nessus, Burp in active mode, etc.
- In theoretical mode: show the exact command ready to copy/paste, with full flags and payload, but do not execute it.
- Never chain requests automatically even if the previous step was approved; each network interaction requires individual approval.
