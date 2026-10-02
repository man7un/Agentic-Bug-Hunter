# New-Program Watcher — Quickstart

Catch newly launched bug bounty programs in their **first-72-hour window**
(before the crowd), across **HackerOne** and **YesWeHack**.

> **Safety model:** detection and prep are automatic and **passive** (they read
> platform metadata, never touch the target). Attacking a target and submitting
> a report always stay a human decision.

---

## How it works

Every 6 hours (and once on login), the watcher automatically:

1. **Detects** new programs on HackerOne + YesWeHack (diffs the public program
   list against a saved snapshot).
2. **Builds a dossier** per new program — in-scope assets ranked by likely
   bug/bounty density, suggested vuln classes, reward/disclosed-report intel.
3. **Notifies** — a clickable desktop popup (Open → browser), and with
   `--launch`, **opens one terminal per program** paused at its approval gate.
4. You **approve** (`/hunt-new`) → a bounded `/autopilot` hunts it → you review
   and **submit** any confirmed finding.

```
detect → dossier (passive) → popup / terminal → you approve → /autopilot → you submit
└──────────── automatic ────────────┘   └──────── human-gated ────────┘
```

Each program runs in its **own** isolated session — never mixed.

---

## Run it yourself

From the repo root (`cd "/home/m/Desktop/bug bounty/claude-bug-bounty"`):

```bash
# Check right now — popup + dossier for anything new
python3 tools/program_watch.py --notify --dossier

# Full auto behaviour (what the cron runs): also open a hunt terminal per hit
python3 tools/program_watch.py --notify --dossier --hunt-cmds --launch

# First-time baseline (records current programs, no alerts)
python3 tools/program_watch.py --seed
```

### Useful flags
| Flag | Effect |
|---|---|
| `--sources h1,ywh` | Pick platforms (default: both) |
| `--keywords saudi,fintech,crypto` | Only alert on handle/name matches |
| `--bounties-only` | Skip reputation-only VDPs |
| `--notify` | Desktop popup per hit (clickable → browser) |
| `--dossier` | Build a scope+rank dossier per hit |
| `--hunt-cmds` | Print an isolated launch command per program |
| `--launch` | Auto-open one terminal per program at its `/hunt-new` gate |
| `--json` | Machine-readable output |

### Dossier on demand
```bash
python3 tools/program_dossier.py shopify --stdout            # HackerOne
python3 tools/program_dossier.py <slug> --source ywh --stdout # YesWeHack
```

### See past finds
```bash
tail -n 40 ~/.program_watch.log
```

---

## It already runs automatically

Two cron entries are installed (`crontab -l` to view):

- **Every 6 hours** — ongoing checks while the PC is on.
- **On login** (`@reboot`, 60s delay) — one check at startup to catch the
  overnight gap.

Both run `program_watch.py --notify --dossier --hunt-cmds --launch` and append
to `~/.program_watch.log`.

**To turn off auto-opening terminals** (keep popups/dossiers): `crontab -e` and
remove `--launch` from the two lines.

---

## Hunting a program (after a popup)

```
/hunt-new <handle>                       # HackerOne (default)
/hunt-new <slug> --source ywh            # YesWeHack
/hunt-new <handle> --mode paranoid       # stop at every signal
/hunt-new <handle> --vuln-class idor     # single-class hunt
```

`/hunt-new` shows the dossier, asks you to authorize active testing of that one
program, and only then hands off to the bounded, scope-checked `/autopilot`.
Report submission is always a separate human step (`/validate` → `/report`).

---

## Files

| Path | What |
|---|---|
| `tools/program_watch.py` | Multi-source new-program watcher |
| `tools/program_dossier.py` | Passive scope + rank dossier builder |
| `commands/hunt-new.md` | `/hunt-new` approval-gate command |
| `memory/program_watch_state.json` | Snapshot of seen programs (gitignored) |
| `findings/dossiers/<handle>-<date>.md` | Generated dossiers (gitignored) |
| `~/.program_watch.log` | Run log |

> Not scraped: **bbradar.io** (anti-bot token+CSRF gate) and **Intigriti** (no
> public program feed — would need a researcher-API token).
