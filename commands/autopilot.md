---
description: Run autonomous hunt loop on a target — scope check → recon → rank surface → hunt → validate → report with configurable checkpoints. Usage: /autopilot target.com [--paranoid|--normal|--yolo]
---

# /autopilot

Autonomous hunt loop with deterministic scope safety and configurable checkpoints.

## Usage

```
/autopilot target.com                    # default: --paranoid mode
/autopilot target.com --normal           # batch checkpoint after validation
/autopilot target.com --yolo             # minimal checkpoints (still requires report approval)
/autopilot target.com --quick            # fast surface scan, fewer checks, lower token use
/autopilot targets.txt                   # multiple targets — one domain per line in the file
```

## Session Isolation (Important)

**Start a fresh Claude Code session per target.** Claude accumulates context across a session —
testing multiple targets in one session causes cross-contamination where findings, payloads,
and tech stack assumptions from target A bleed into target B.

Best practice:
```bash
# Terminal 1: target A
claude  →  /autopilot targetA.com

# Terminal 2: target B (separate process)
claude  →  /autopilot targetB.com
```

If you must test multiple targets in one session, run `/pickup target.com` at the start of
each target switch to reload the correct context.

## Token Optimization

Use `--quick` for faster, lower-cost scans (skips deep fuzzing and extended nuclei templates):
```
/autopilot target.com --quick    # ~40% fewer tokens, covers main attack surface
/hunt target.com --vuln-class idor   # single bug class — lowest token use
```

For long hunts, run `/compact` (Claude Code built-in) periodically to compress context
without losing findings.

## What This Does

Runs the full hunt cycle without stopping for approval at each step:

```
1. SCOPE     Load and confirm program scope
2. RECON     Run recon (or use cached if < 7 days old)
3. RANK      Prioritize attack surface (recon-ranker agent)
4. HUNT      Test P1 endpoints systematically; run tools/confirm_*.py on any
             IDOR/SSRF/auth-bypass/XSS signal before treating it as a finding
5. VALIDATE  7-Question Gate — Gates 1/3 read the confirm_*.py proof.json when one
             exists, instead of self-report
6. REPORT    Draft reports for validated findings
7. CHECKPOINT  Present to human for review — fires early on a CONFIRMED finding,
             or when the hunt budget (default 200 requests / 90 min) runs out
```

## Automated Exploit Confirmation

Four vuln classes get an independent, mechanical re-check instead of relying on
Claude's own account of what it saw — see `tools/confirm_idor.py`,
`tools/confirm_ssrf.py`, `tools/confirm_authbypass.py`, `tools/confirm_xss.py`.
Each writes a `proof.json` with a verdict of `CONFIRMED`, `POSSIBLE`, or
`UNCONFIRMED`; `/validate --proof <path>` reads it and will not let a `POSSIBLE`
or `UNCONFIRMED` verdict be talked past. Findings outside these four classes still
go through the standard self-attested 7-Question Gate — the report will say so.

## Safety Guarantees

- **Every URL** is checked against the scope allowlist before any request
- **Every request** is logged to `hunt-memory/audit.jsonl`
- **Reports are NEVER auto-submitted** — always requires explicit approval
- **PUT/DELETE/PATCH** require human approval in --yolo mode (safe methods only)
- **Circuit breaker** stops hammering if 5 consecutive 403/429/timeout on same host
- **Rate limited** at 1 req/sec (testing) and 10 req/sec (recon)

## Checkpoint Modes

| Mode | When it stops | Best for |
|---|---|---|
| `--paranoid` | Every finding + partial signal | New targets, learning the surface |
| `--normal` | After validation batch | Systematic coverage |
| `--yolo` | After full surface exhausted | Familiar targets, experienced hunters |

## After Autopilot

- Run `/remember` to log successful patterns to hunt memory
- Run `/pickup target.com` next time to pick up where you left off
- Check `hunt-memory/audit.jsonl` for a full request log
