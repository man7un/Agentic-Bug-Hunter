#!/usr/bin/env python3
"""program_watch.py — detect newly launched bug bounty programs.

Polls HackerOne's PUBLIC program directory (the same unauthenticated GraphQL
endpoint mcp/hackerone-mcp uses) and diffs the open-program set by handle
against a stored snapshot. Any handle that appears which wasn't in the previous
snapshot is a newly launched / newly public program — the first-72-hours window
where competition is thinnest.

Why not bbradar.io: its API is gated behind a frontend-token + CSRF + session
flow (a deliberate anti-bot measure), so polling it means defeating an access
control they intentionally put up. This hits a source that is meant to be read.

Usage:
    program_watch.py --seed                  # establish baseline, no alerts
    program_watch.py                          # poll, print newly appeared programs
    program_watch.py --keywords zain,saudi,fintech   # only alert on matches
    program_watch.py --bounties-only          # only paying programs
    program_watch.py --json                   # machine-readable output

Exit codes: 0 = ran OK (new programs may or may not have been found),
            1 = network/API error (safe for a loop to retry later).
Stdlib only — no third-party deps.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request

H1_GRAPHQL = "https://hackerone.com/graphql"
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATE_PATH = os.path.join(BASE_DIR, "memory", "program_watch_state.json")
USER_AGENT = "claude-bug-bounty/program-watch"
PAGE_SIZE = 100
MAX_PAGES = 12  # safety cap; ~1200 programs max per poll
PAGE_DELAY_S = 1.0  # be polite between pages

try:
    _SSL_CTX = ssl.create_default_context()
except Exception:  # pragma: no cover
    _SSL_CTX = None


def _graphql(query: str, timeout: int = 20) -> dict:
    payload = json.dumps({"query": query}).encode("utf-8")
    req = urllib.request.Request(
        H1_GRAPHQL,
        data=payload,
        headers={"Content-Type": "application/json", "User-Agent": USER_AGENT},
    )
    with urllib.request.urlopen(req, timeout=timeout, context=_SSL_CTX) as resp:
        data = json.loads(resp.read().decode("utf-8", errors="replace"))
    if "errors" in data:
        raise RuntimeError(f"GraphQL errors: {data['errors']}")
    return data


def fetch_open_programs() -> dict[str, dict]:
    """Return {handle: {name, offers_bounties, url}} for all open H1 programs."""
    programs: dict[str, dict] = {}
    after = ""
    for _ in range(MAX_PAGES):
        after_arg = f', after: "{after}"' if after else ""
        query = (
            "query { teams(first: %d%s, where: {submission_state: {_eq: open}}) "
            "{ pageInfo { hasNextPage endCursor } "
            "edges { node { handle name offers_bounties url } } } }"
            % (PAGE_SIZE, after_arg)
        )
        data = _graphql(query)
        teams = data["data"]["teams"]
        for edge in teams["edges"]:
            n = edge["node"]
            programs[n["handle"]] = {
                "name": n.get("name") or n["handle"],
                "offers_bounties": bool(n.get("offers_bounties")),
                "url": n.get("url") or f"https://hackerone.com/{n['handle']}",
            }
        if not teams["pageInfo"]["hasNextPage"]:
            break
        after = teams["pageInfo"]["endCursor"]
        time.sleep(PAGE_DELAY_S)
    return programs


def load_state() -> dict:
    try:
        with open(STATE_PATH, encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def save_state(seen: dict[str, dict]) -> None:
    os.makedirs(os.path.dirname(STATE_PATH), exist_ok=True)
    tmp = STATE_PATH + ".tmp"
    payload = {
        "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "source": "hackerone-public-directory",
        "programs": seen,
    }
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
    os.replace(tmp, STATE_PATH)  # atomic


def desktop_notify(hits: list[dict]) -> None:
    """Fire a single best-effort desktop popup summarizing the hits.

    Never raises: notify-send may be missing, or (common under cron) the
    D-Bus/display session may be unreachable. A failed popup must not fail the
    poll, so all errors are swallowed — the log line is the source of truth.
    """
    if not hits or not shutil.which("notify-send"):
        return
    title = f"🎯 {len(hits)} new bug bounty program(s)"
    lines = []
    for p in hits[:8]:
        tag = "💰" if p["offers_bounties"] else "VDP"
        lines.append(f"• {p['name']} [{p['handle']}] — {tag}")
    if len(hits) > 8:
        lines.append(f"…and {len(hits) - 8} more")
    body = "\n".join(lines)
    try:
        subprocess.run(
            ["notify-send", "--urgency=normal", "--app-name=program_watch",
             title, body],
            timeout=10, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        pass


def matches(prog: dict, handle: str, keywords: list[str]) -> bool:
    if not keywords:
        return True
    hay = f"{handle} {prog['name']}".lower()
    return any(k in hay for k in keywords)


def main() -> int:
    ap = argparse.ArgumentParser(description="Watch for newly launched H1 programs.")
    ap.add_argument("--seed", action="store_true",
                    help="Establish baseline snapshot without alerting.")
    ap.add_argument("--keywords", default="",
                    help="Comma-separated terms; only alert on handle/name matches.")
    ap.add_argument("--bounties-only", action="store_true",
                    help="Only alert on programs that pay bounties.")
    ap.add_argument("--json", action="store_true", help="Emit JSON.")
    ap.add_argument("--notify", action="store_true",
                    help="Also fire a desktop popup (notify-send) when there are hits.")
    args = ap.parse_args()

    keywords = [k.strip().lower() for k in args.keywords.split(",") if k.strip()]

    try:
        current = fetch_open_programs()
    except (urllib.error.URLError, urllib.error.HTTPError, RuntimeError, TimeoutError) as e:
        print(f"[program_watch] API error (will retry next poll): {e}", file=sys.stderr)
        return 1

    if not current:
        print("[program_watch] fetched 0 programs — treating as transient, not updating state.",
              file=sys.stderr)
        return 1

    state = load_state()
    prev = state.get("programs", {})

    if args.seed or not prev:
        save_state(current)
        msg = f"Seeded baseline: {len(current)} open programs. Future polls report new arrivals."
        print(json.dumps({"seeded": len(current)}) if args.json else f"[program_watch] {msg}")
        return 0

    new_handles = [h for h in current if h not in prev]
    hits = []
    for h in new_handles:
        p = current[h]
        if args.bounties_only and not p["offers_bounties"]:
            continue
        if matches(p, h, keywords):
            hits.append({"handle": h, **p})

    # Persist the full current set so a program is reported only once.
    save_state(current)

    if args.notify:
        desktop_notify(hits)

    if args.json:
        print(json.dumps({
            "total_open": len(current),
            "new_since_last_poll": len(new_handles),
            "matching_alerts": hits,
        }, indent=2))
        return 0

    if not hits:
        extra = f" ({len(new_handles)} new, none matched filters)" if new_handles else ""
        print(f"[program_watch] No new matching programs{extra}. Total open: {len(current)}.")
        return 0

    print(f"[program_watch] {len(hits)} NEW program(s) to hunt "
          f"(first-72h window) — total open now {len(current)}:")
    for p in hits:
        tag = "💰 pays bounties" if p["offers_bounties"] else "VDP (rep only)"
        print(f"  • {p['name']}  [{p['handle']}]  — {tag}\n    {p['url']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
