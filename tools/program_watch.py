#!/usr/bin/env python3
"""program_watch.py — detect newly launched bug bounty programs (multi-source).

Polls each enabled platform's PUBLIC program directory and diffs the program
set against a stored snapshot. Any program that appears which wasn't in the
previous snapshot is newly launched / newly public — the first-72-hours window
where competition is thinnest. Programs are keyed `<source>:<id>` so platforms
never collide and each can be tracked independently.

Sources (all read endpoints that are MEANT to be consumed — none are scraped
past an anti-bot gate):
  - h1  — HackerOne public program directory (unauthenticated GraphQL, the same
          endpoint mcp/hackerone-mcp uses).
  - ywh — YesWeHack public programs API (https://api.yeswehack.com/programs).
  - intigriti — NOT wired: Intigriti exposes no public program feed (its data is
          behind the authenticated researcher API). See the stub below; it only
          activates if an API token is provided. We do not scrape it, same call
          we made on bbradar.io (whose API is gated behind a frontend-token +
          CSRF + session flow).

Usage:
    program_watch.py --seed                  # establish baseline, no alerts
    program_watch.py                          # poll, print newly appeared programs
    program_watch.py --sources h1,ywh        # pick sources (default: all public)
    program_watch.py --keywords zain,saudi   # only alert on handle/name matches
    program_watch.py --bounties-only          # only paying programs
    program_watch.py --notify --dossier       # desktop popup + H1 scope dossier
    program_watch.py --json                   # machine-readable output

Exit codes: 0 = ran OK, 1 = all sources failed / network error (safe to retry).
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


YWH_API = "https://api.yeswehack.com/programs"


def _http_json(url: str, timeout: int = 20) -> dict:
    req = urllib.request.Request(
        url, headers={"Accept": "application/json", "User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout, context=_SSL_CTX) as resp:
        return json.loads(resp.read().decode("utf-8", errors="replace"))


def fetch_hackerone() -> dict[str, dict]:
    """All open HackerOne programs, keyed `h1:<handle>`."""
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
        teams = _graphql(query)["data"]["teams"]
        for edge in teams["edges"]:
            n = edge["node"]
            handle = n["handle"]
            programs[f"h1:{handle}"] = {
                "source": "h1", "platform": "HackerOne", "handle": handle,
                "name": n.get("name") or handle,
                "offers_bounties": bool(n.get("offers_bounties")),
                "url": n.get("url") or f"https://hackerone.com/{handle}",
            }
        if not teams["pageInfo"]["hasNextPage"]:
            break
        after = teams["pageInfo"]["endCursor"]
        time.sleep(PAGE_DELAY_S)
    return programs


def fetch_yeswehack() -> dict[str, dict]:
    """All public YesWeHack programs, keyed `ywh:<slug>`."""
    programs: dict[str, dict] = {}
    page = 1
    while page <= MAX_PAGES:
        data = _http_json(f"{YWH_API}?page={page}")
        for it in data.get("items", []):
            # Only live, public, non-archived programs are hunt targets.
            if it.get("disabled") or it.get("archived") or not it.get("public", True):
                continue
            slug = it.get("slug")
            if not slug:
                continue
            programs[f"ywh:{slug}"] = {
                "source": "ywh", "platform": "YesWeHack", "handle": slug,
                "name": it.get("title") or slug,
                "offers_bounties": bool(it.get("bounty")),
                "url": f"https://yeswehack.com/programs/{slug}",
            }
        pag = data.get("pagination") or {}
        if page >= int(pag.get("nb_pages", page)):
            break
        page += 1
        time.sleep(PAGE_DELAY_S)
    return programs


def fetch_intigriti() -> dict[str, dict]:
    """Intigriti has no public program feed — its data is behind the
    authenticated researcher API. Not wired by default; left as a stub so the
    source can be added later with an API token (e.g. via tools/credential_store).
    We do not scrape the SPA/gated endpoints."""
    raise RuntimeError(
        "intigriti source not available: no public program feed (needs the "
        "authenticated researcher API). Supply a token and implement here.")


# source name → fetcher. Only public, consume-friendly sources are enabled.
SOURCES = {
    "h1": fetch_hackerone,
    "ywh": fetch_yeswehack,
    # "intigriti": fetch_intigriti,  # disabled: no public feed (see fetch_intigriti)
}
DEFAULT_SOURCES = ["h1", "ywh"]


def fetch_all(selected: list[str], prev: dict[str, dict]) -> tuple[dict[str, dict], list[str]]:
    """Fetch every selected source. Returns (current_snapshot, failed_sources).

    A source that errors does NOT drop its programs from the snapshot — its
    previous entries are carried over so they aren't re-alerted as 'new' on the
    next successful poll. New-program detection is skipped for failed sources.
    """
    current: dict[str, dict] = {}
    failed: list[str] = []
    for name in selected:
        fetcher = SOURCES.get(name)
        if fetcher is None:
            print(f"[program_watch] unknown/disabled source '{name}', skipping.",
                  file=sys.stderr)
            failed.append(name)
            continue
        try:
            current.update(fetcher())
        except (urllib.error.URLError, urllib.error.HTTPError, RuntimeError,
                TimeoutError, json.JSONDecodeError, KeyError) as e:
            print(f"[program_watch] source '{name}' failed (carrying over prior "
                  f"entries): {e}", file=sys.stderr)
            failed.append(name)
    # Carry over prior entries for any source NOT freshly fetched this run —
    # both failed sources AND sources not in `selected`. Without this, a subset
    # poll (e.g. --sources ywh) would drop the other sources from the snapshot
    # and re-alert their whole catalogue on the next full poll.
    succeeded = set(selected) - set(failed)
    for key, val in prev.items():
        if key.split(":", 1)[0] not in succeeded and key not in current:
            current[key] = val
    return current, failed


def load_state() -> dict:
    try:
        with open(STATE_PATH, encoding="utf-8") as f:
            state = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}
    # Migrate legacy single-source snapshots (bare H1 handles, no source prefix)
    # to the `h1:<handle>` keyspace so the first multi-source poll doesn't
    # re-alert every existing H1 program as "new".
    progs = state.get("programs", {})
    if progs and not any(":" in k for k in progs):
        state["programs"] = {
            f"h1:{k}": {"source": "h1", "platform": "HackerOne", "handle": k, **v}
            for k, v in progs.items()
        }
    return state


def save_state(seen: dict[str, dict]) -> None:
    os.makedirs(os.path.dirname(STATE_PATH), exist_ok=True)
    tmp = STATE_PATH + ".tmp"
    payload = {
        "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "source": "multi",
        "programs": seen,
    }
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
    os.replace(tmp, STATE_PATH)  # atomic


# Clickable action: notify-send --action implies --wait (it blocks until the
# user clicks or the popup closes), so each popup runs detached and under a
# `timeout` cap — it must never block or outlive the poll. On click, the action
# key "open" is printed to stdout and we xdg-open the program URL. T/B/U are
# passed via the environment, never interpolated, so a program name with quotes
# can't break or inject into the shell.
_CLICK_SCRIPT = (
    'sel=$(notify-send --urgency=normal --app-name=program_watch '
    '--action=open=Open "$T" "$B"); '
    '[ "$sel" = open ] && xdg-open "$U" >/dev/null 2>&1'
)
_NOTIFY_MAX = 6          # cap simultaneous popups
_NOTIFY_TTL = "600"      # seconds a waiting popup may linger before timeout kills it


def build_dossier(handle: str, source: str = "h1") -> str | None:
    """Run program_dossier.py for a handle; return the written path, or None.

    Best-effort: the dossier is a convenience, so any failure (network, the
    program vanished between poll and dossier, a broken sibling tool) is logged
    and skipped rather than failing the poll. The tool prints the path as its
    last stdout line.
    """
    tool = os.path.join(os.path.dirname(os.path.abspath(__file__)), "program_dossier.py")
    try:
        proc = subprocess.run(
            [sys.executable, tool, handle, "--source", source],
            capture_output=True, text=True, timeout=60,
        )
    except (OSError, subprocess.SubprocessError) as e:
        print(f"[program_watch] dossier for {handle} failed: {e}", file=sys.stderr)
        return None
    if proc.returncode != 0:
        print(f"[program_watch] dossier for {handle} exited {proc.returncode}: "
              f"{proc.stderr.strip()}", file=sys.stderr)
        return None
    lines = [ln for ln in proc.stdout.splitlines() if ln.strip()]
    return lines[-1] if lines else None


def desktop_notify(hits: list[dict]) -> None:
    """Fire best-effort desktop popups for new programs — one clickable popup
    per hit (Open button → browser), capped at _NOTIFY_MAX.

    Never raises and never blocks the poll: popups are spawned detached. If the
    click toolchain (xdg-open/timeout) is missing, falls back to a single
    non-clickable summary. The log line remains the source of truth.
    """
    if not hits or not shutil.which("notify-send"):
        return

    clickable = shutil.which("xdg-open") and shutil.which("timeout")
    try:
        if clickable:
            for p in hits[:_NOTIFY_MAX]:
                tag = "💰 pays bounties" if p["offers_bounties"] else "VDP (rep only)"
                body = f"{p['handle']} — {tag}\nClick Open to view on HackerOne."
                if p.get("dossier"):
                    body += f"\nDossier: {p['dossier']}"
                env = {
                    **os.environ,
                    "T": f"🎯 New {p.get('platform', 'program')}: {p['name']}",
                    "B": body,
                    "U": p["url"],
                }
                subprocess.Popen(
                    ["timeout", _NOTIFY_TTL, "bash", "-c", _CLICK_SCRIPT],
                    env=env, start_new_session=True,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                )
            if len(hits) > _NOTIFY_MAX:
                subprocess.Popen(
                    ["notify-send", "--app-name=program_watch",
                     f"🎯 +{len(hits) - _NOTIFY_MAX} more new program(s)",
                     "See ~/.program_watch.log for the full list."],
                    start_new_session=True,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                )
        else:
            # Fallback: single non-clickable summary popup.
            lines = []
            for p in hits[:8]:
                tag = "💰" if p["offers_bounties"] else "VDP"
                lines.append(f"• {p['name']} [{p['handle']}] — {tag}")
            if len(hits) > 8:
                lines.append(f"…and {len(hits) - 8} more")
            subprocess.run(
                ["notify-send", "--urgency=normal", "--app-name=program_watch",
                 f"🎯 {len(hits)} new bug bounty program(s)", "\n".join(lines)],
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
    ap.add_argument("--dossier", action="store_true",
                    help="Auto-build a scope+rank dossier (program_dossier.py) per new "
                         "HackerOne program and attach its path to the alert.")
    ap.add_argument("--sources", default=",".join(DEFAULT_SOURCES),
                    help=f"Comma-separated sources to poll (default: "
                         f"{','.join(DEFAULT_SOURCES)}). Available: {','.join(SOURCES)}.")
    args = ap.parse_args()

    keywords = [k.strip().lower() for k in args.keywords.split(",") if k.strip()]
    selected = [s.strip() for s in args.sources.split(",") if s.strip()]

    state = load_state()
    prev = state.get("programs", {})

    current, failed = fetch_all(selected, prev)

    if len(failed) == len(selected):
        print("[program_watch] all sources failed — not updating state (will retry).",
              file=sys.stderr)
        return 1
    if not current:
        print("[program_watch] fetched 0 programs — treating as transient, not updating state.",
              file=sys.stderr)
        return 1

    if args.seed or not prev:
        save_state(current)
        by_src = {}
        for v in current.values():
            by_src[v["source"]] = by_src.get(v["source"], 0) + 1
        msg = (f"Seeded baseline: {len(current)} programs "
               f"({', '.join(f'{k}={n}' for k, n in sorted(by_src.items()))}). "
               "Future polls report new arrivals.")
        print(json.dumps({"seeded": len(current), "by_source": by_src})
              if args.json else f"[program_watch] {msg}")
        return 0

    # A program is "new" only if (a) it wasn't in the snapshot, (b) its source
    # fetched OK this run, and (c) that source was already baselined. A source
    # appearing for the first time (e.g. ywh added to an H1-only snapshot) is
    # absorbed silently rather than alerting its entire catalogue at once.
    prev_sources = {k.split(":", 1)[0] for k in prev}
    new_keys = [k for k in current
                if k not in prev
                and k.split(":", 1)[0] not in failed
                and k.split(":", 1)[0] in prev_sources]
    newly_baselined = sorted({
        k.split(":", 1)[0] for k in current
        if k.split(":", 1)[0] not in prev_sources and k.split(":", 1)[0] not in failed
    })
    if newly_baselined:
        print(f"[program_watch] baselined new source(s) silently: "
              f"{', '.join(newly_baselined)} (future arrivals will alert).",
              file=sys.stderr)
    hits = []
    for k in new_keys:
        p = current[k]
        if args.bounties_only and not p["offers_bounties"]:
            continue
        if matches(p, p["handle"], keywords):
            hits.append({"key": k, **p})

    # Persist the full current set so a program is reported only once.
    save_state(current)

    # Auto-build a hunt dossier (passive scope+rank+intel) per new program.
    # Supported for both HackerOne and YesWeHack (program_dossier --source).
    if args.dossier and hits:
        for p in hits:
            if p["source"] in ("h1", "ywh"):
                p["dossier"] = build_dossier(p["handle"], p["source"])

    if args.notify:
        desktop_notify(hits)

    if args.json:
        print(json.dumps({
            "total_tracked": len(current),
            "sources_polled": selected,
            "sources_failed": failed,
            "new_since_last_poll": len(new_keys),
            "matching_alerts": hits,
        }, indent=2))
        return 0

    if not hits:
        extra = f" ({len(new_keys)} new, none matched filters)" if new_keys else ""
        failnote = f" [sources failed: {','.join(failed)}]" if failed else ""
        print(f"[program_watch] No new matching programs{extra}. "
              f"Tracking {len(current)}.{failnote}")
        return 0

    print(f"[program_watch] {len(hits)} NEW program(s) to hunt "
          f"(first-72h window) — tracking {len(current)}:")
    for p in hits:
        tag = "💰 pays bounties" if p["offers_bounties"] else "VDP (rep only)"
        print(f"  • [{p['platform']}] {p['name']}  [{p['handle']}]  — {tag}\n    {p['url']}")
        if p.get("dossier"):
            print(f"    dossier: {p['dossier']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
