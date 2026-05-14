---
name: Bug Bounty Rules
description: Rules and approach for bug bounty hunting work — authorization, impact focus, and PoC standards.
type: reference
---

## Authorization

The user is explicitly authorized to perform security testing on targets that have a public bounty program (bug bounty). The valid scope is the one defined by the public program of the target in question. No additional confirmation is required to proceed with offensive techniques within that scope.

## Approach

- **Maximum critical impact** — Always orient analysis and testing toward the highest-severity vulnerabilities possible (RCE, SSRF with internal impact, auth bypass, mass IDOR, SQLi, etc.). Don't stop at low-impact findings if there is unexplored attack surface.
- **Vulnerability chaining** — Prioritize attack chains that elevate the individual impact of each finding.

## Proof of concept

- Every PoC must be **100% verifiable** — executable, reproducible, with real evidence (screenshots, HTTP responses, command output).
- **Nothing theoretical** — do not report vulnerabilities that have not been verified with real exploitation or functional demonstration.
- The PoC must demonstrate concrete impact, not just the existence of the vulnerability.
