---
name: Ripgrep/grep usage and pre-authorization
description: Prefer ripgrep over grep, and user has pre-authorized both tools so no confirmation is ever needed
type: feedback
originSessionId: 6673f0e2-c178-4809-8cc5-5301467e98a9
---

1. Always invoke `rg` (ripgrep) instead of `grep`/`egrep`/`fgrep` for text search.
2. Both `rg` and `grep` are pre-authorized — never ask for permission or pause for confirmation, just run them.

**Why:** Explicit user preferences stated on 2026-05-05. Ripgrep is faster and has better defaults; the user wants frictionless searching during pentest/triage workflows where confirmation prompts add noise.

**How to apply:**
- Default to `rg` for any new search; only fall back to `grep` if `rg` is unavailable in the environment.
- For both tools, treat invocations as authorized — do not preface with "I'll run grep, ok?" or similar. Just execute.
- Authorization covers piped searches (`cmd | rg pattern`), recursive (`rg -r`), and any flag combination. It does NOT extend to other tools chained alongside.

**Note:** This is better expressed long-term as a permissions allowlist in `settings.json` (the harness enforces it without needing the model to remember), but the user requested a memory entry, so this is the durable record. If the user later wants to make this harness-enforced, suggest the `update-config` skill to add `Bash(rg:*)` and `Bash(grep:*)` to allowlist.
