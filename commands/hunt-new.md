---
description: Approval gate for a newly detected program (HackerOne or YesWeHack) — reads/builds its dossier, shows scope + ranked surface, then (only on explicit human approval) kicks off a bounded, scope-checked /autopilot hunt. Usage: /hunt-new <handle> [--source h1|ywh] [--mode paranoid|normal|yolo] [--vuln-class <class>]
---

# /hunt-new

The bridge between **detection** (`tools/program_watch.py`) and **hunting**
(`/autopilot`). It turns a newly launched program into a reviewed, authorized
hunt — with a mandatory human approval gate in the middle. Nothing in this
command sends active traffic at the target until you explicitly approve.

## Usage

```
/hunt-new shopify                              # HackerOne (default source)
/hunt-new infomaniak-bug-bounty-program --source ywh   # YesWeHack
/hunt-new shopify --mode paranoid              # stop at every finding/signal
/hunt-new shopify --vuln-class idor            # single-class hunt via /hunt
```

`<handle>` is the program's handle/slug as it appears in `program_watch` alerts
(the `[HackerOne]` / `[YesWeHack]` tag tells you the source). `--source` is
`h1` (default) or `ywh`. Default mode is `--normal`.

## Steps (follow in order)

### 1. Resolve the source, then load the dossier — do NOT touch the target yet
- **Source:** use `--source` if given. If omitted, default to `h1`; if the
  dossier build then reports "not found on h1" (exit 2), retry once with
  `--source ywh` before giving up (the `program_watch` alert's platform tag is
  the authoritative hint if you have it).
- Look for the newest `findings/dossiers/<handle>-*.md`. Confirm its
  **`Platform:`** line matches the source you intend; if it doesn't, rebuild.
- To build (or refresh) it: `python3 tools/program_dossier.py <handle> --source <src>`
  — this is **passive** (reads platform metadata only, sends no traffic to the
  target). Then read the file it writes.
- If `program_dossier.py` exits non-zero on the resolved source (program not
  found / API error), stop and report that — do not improvise a target.

### 2. Present the brief to the human
Summarize from the dossier, concisely:
- Program name, handle, **platform**, URL, and whether it **pays bounties** or is a VDP.
- The **top 5 ranked in-scope assets** (with their scores/signals).
- Any **out-of-scope / non-submittable** assets (so they're not touched) — H1
  lists these as non-submittable scopes, YesWeHack as out-of-scope notes.
- **Suggested vuln classes** for the first passes.
- The dossier's **intel** section: disclosed reports (HackerOne) or reward range
  + qualifying vulns (YesWeHack), if present.
- The single **proposed first target**: the top-ranked *submittable* asset. If
  it's a wildcard (`*.example.com`), say recon will enumerate concrete hosts
  under it.

### 3. THE APPROVAL GATE (mandatory — this is the whole point)
Stop and ask the human to authorize active testing, explicitly. Make clear:
- which target + mode you're about to launch,
- that this begins **active testing of a live third-party system**,
- that they are confirming the asset is **in scope and they're authorized** to test it.

Ask with a clear yes/no (an `AskUserQuestion` is ideal). **Proceed only on an
unambiguous "yes."** If the answer is no, unclear, or "let me read it first,"
**do not start** — stop here and let them decide. Never infer approval from
earlier messages; this gate is per-program and must be answered now.

If the human wants a different target than the proposed one (e.g. a specific
host under a wildcard, or the #2 asset), use theirs — but it must be one of the
dossier's **submittable in-scope** assets. Refuse out-of-scope / non-submittable
targets.

### 4. Hand off to the bounded hunt (only after approval)
- Default / `--mode <m>`: run `/autopilot <approved-target> --<mode>` (default
  `--normal`). Autopilot re-checks every URL against scope, rate-limits, runs
  the `confirm_*.py` proof harnesses on IDOR/SSRF/auth-bypass/XSS signals, and
  obeys the hunt budget (≈200 req / 90 min).
- `--vuln-class <class>`: run `/hunt <approved-target> --vuln-class <class>`
  instead (lighter, single-class).
- Remind the human once: **submission is still human-gated** — autopilot never
  auto-submits, in any mode.

## Safety invariants (never bypass)
- No active traffic before the Step 3 approval. The dossier stage is passive.
- Only ever hand off a target that is **submittable and in scope** per the dossier.
- This command authorizes **testing**, not **submitting** — report submission
  remains a separate human decision (`/validate` → `/report`).
- One program per approval. Re-run `/hunt-new` for the next program; don't batch.

## Relationship to the pipeline
```
program_watch (detect) → program_dossier (passive scope+rank) → /hunt-new (YOU approve) → /autopilot (bounded hunt) → /validate → /report (YOU submit)
```
Everything left of "/hunt-new approve" is automatic and passive. Everything from
the approval rightward touches the target and stays under human control.
