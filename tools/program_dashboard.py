#!/usr/bin/env python3
"""program_dashboard.py — a local status page for the new-program watcher.

Serves a small auto-refreshing web page (stdlib http.server, no deps) that reads
the watcher's live state + log and shows, at a glance:
  - health (is it checking on schedule?)
  - last check time + programs tracked per source
  - recent newly-found programs (with links + dossier paths)

Open http://127.0.0.1:8787 in a browser. It reads the files fresh on every
request, so it is always current.

Usage:
    program_dashboard.py                 # serve on 127.0.0.1:8787 (localhost only)
    program_dashboard.py --port 9000
    program_dashboard.py --host 0.0.0.0  # expose on your LAN (phone access) — see note

Security: default binds to localhost only. --host 0.0.0.0 exposes the page to
anyone on your network; the page is read-only status but still reveals which
programs you're watching, so only do it on a trusted network.
"""
from __future__ import annotations

import argparse
import datetime as dt
import html
import json
import os
import re
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATE_PATH = os.path.join(BASE_DIR, "memory", "program_watch_state.json")
LOG_PATH = os.path.expanduser("~/.program_watch.log")
# One 6h cycle + a little slack: if no successful check within this, flag stale.
HEALTHY_WINDOW_S = 7 * 3600
REFRESH_S = 30


def _load_state() -> dict:
    try:
        with open(STATE_PATH, encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _age_seconds(iso_z: str) -> float | None:
    try:
        t = dt.datetime.strptime(iso_z, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=dt.timezone.utc)
        return (dt.datetime.now(dt.timezone.utc) - t).total_seconds()
    except (ValueError, TypeError):
        return None


def _human_age(sec: float | None) -> str:
    if sec is None:
        return "unknown"
    sec = int(sec)
    if sec < 60:
        return f"{sec}s ago"
    if sec < 3600:
        return f"{sec // 60}m ago"
    if sec < 86400:
        return f"{sec // 3600}h {sec % 3600 // 60}m ago"
    return f"{sec // 86400}d ago"


def _parse_log(max_finds: int = 20) -> tuple[list[dict], int, str]:
    """Return (recent finds newest-first, total run count, last log line)."""
    try:
        with open(LOG_PATH, encoding="utf-8", errors="replace") as f:
            lines = f.read().splitlines()
    except FileNotFoundError:
        return [], 0, ""
    finds: list[dict] = []
    run_count = 0
    cur_run = ""
    last_status = ""
    i = 0
    while i < len(lines):
        ln = lines[i]
        if ln.startswith("=== "):
            run_count += 1
            cur_run = ln.strip("= ").strip()
        elif ln.startswith("[program_watch]"):
            last_status = ln
        elif ln.strip().startswith("• ["):
            # "  • [HackerOne] Name  [handle]  — 💰 pays bounties"
            m = re.match(r"\s*•\s*\[([^\]]+)\]\s*(.+?)\s*\[([^\]]+)\]\s*—\s*(.+)",
                         ln)
            url = ""
            dossier = ""
            if i + 1 < len(lines) and lines[i + 1].strip().startswith("http"):
                url = lines[i + 1].strip()
            if i + 2 < len(lines) and lines[i + 2].strip().startswith("dossier:"):
                dossier = lines[i + 2].strip()[len("dossier:"):].strip()
            if m:
                finds.append({
                    "platform": m.group(1), "name": m.group(2).strip(),
                    "handle": m.group(3), "tag": m.group(4).strip(),
                    "url": url, "dossier": dossier, "when": cur_run,
                })
        i += 1
    finds.reverse()
    return finds[:max_finds], run_count, last_status


def render() -> str:
    state = _load_state()
    progs = state.get("programs", {})
    by_src: dict[str, int] = {}
    for v in progs.values():
        by_src[v.get("source", "?")] = by_src.get(v.get("source", "?"), 0) + 1
    updated = state.get("updated_at", "")
    age = _age_seconds(updated)
    healthy = age is not None and age <= HEALTHY_WINDOW_S
    finds, run_count, last_status = _parse_log()

    status_color = "#3fb950" if healthy else "#f85149"
    status_text = "RUNNING" if healthy else ("STALE — last check too long ago"
                                             if age is not None else "NO DATA YET")
    src_labels = {"h1": "HackerOne", "ywh": "YesWeHack"}
    src_rows = "".join(
        f'<span class="pill"><b>{html.escape(src_labels.get(k, k))}</b> {n}</span>'
        for k, n in sorted(by_src.items())
    ) or '<span class="pill">no snapshot yet — run with --seed</span>'

    find_rows = ""
    for fnd in finds:
        link = (f'<a href="{html.escape(fnd["url"])}" target="_blank">open</a>'
                if fnd["url"] else "")
        doss = (f' · <span class="dim">dossier: {html.escape(os.path.basename(fnd["dossier"]))}</span>'
                if fnd["dossier"] else "")
        find_rows += (
            f'<tr><td class="dim">{html.escape(fnd["when"])}</td>'
            f'<td><span class="plat">{html.escape(fnd["platform"])}</span></td>'
            f'<td><b>{html.escape(fnd["name"])}</b> '
            f'<span class="dim">[{html.escape(fnd["handle"])}]</span></td>'
            f'<td>{html.escape(fnd["tag"])}</td>'
            f'<td>{link}{doss}</td></tr>'
        )
    if not find_rows:
        find_rows = ('<tr><td colspan="5" class="dim">No new programs logged yet. '
                     'The watcher logs a line every run; new ones show here.</td></tr>')

    return f"""<!doctype html>
<html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="refresh" content="{REFRESH_S}">
<title>Program Watcher — status</title>
<style>
  :root {{ color-scheme: dark; }}
  body {{ font: 15px/1.5 -apple-system, Segoe UI, Roboto, sans-serif;
          background:#0d1117; color:#c9d1d9; margin:0; padding:16px; }}
  .wrap {{ max-width: 820px; margin: 0 auto; }}
  h1 {{ font-size: 20px; margin: 0 0 4px; }}
  .status {{ display:flex; align-items:center; gap:10px; padding:14px 16px;
             border-radius:10px; background:#161b22; border:1px solid #30363d;
             margin:12px 0; }}
  .dot {{ width:14px; height:14px; border-radius:50%; background:{status_color};
          box-shadow:0 0 10px {status_color}; }}
  .big {{ font-size:18px; font-weight:700; color:{status_color}; }}
  .grid {{ display:flex; flex-wrap:wrap; gap:8px; margin:8px 0 16px; }}
  .pill {{ background:#161b22; border:1px solid #30363d; border-radius:20px;
           padding:5px 12px; font-size:13px; }}
  .plat {{ background:#1f6feb22; border:1px solid #1f6feb55; border-radius:6px;
           padding:1px 7px; font-size:12px; }}
  table {{ width:100%; border-collapse:collapse; font-size:13px; }}
  td {{ padding:7px 8px; border-bottom:1px solid #21262d; vertical-align:top; }}
  .dim {{ color:#8b949e; }}
  a {{ color:#58a6ff; }}
  .foot {{ color:#8b949e; font-size:12px; margin-top:16px; }}
</style></head>
<body><div class="wrap">
  <h1>🎯 Program Watcher</h1>
  <div class="dim">Live status of the new-program hunt pipeline (HackerOne + YesWeHack)</div>

  <div class="status">
    <span class="dot"></span>
    <div>
      <div class="big">{status_text}</div>
      <div class="dim">Last check: {html.escape(updated or "—")} ({_human_age(age)})
        · checks every 6h · {run_count} runs logged</div>
    </div>
  </div>

  <div><b>Tracking</b> {len(progs)} programs:</div>
  <div class="grid">{src_rows}</div>

  <div><b>Recent new programs found</b></div>
  <table>
    <tr><td class="dim">when</td><td class="dim">platform</td><td class="dim">program</td>
        <td class="dim">type</td><td class="dim">links</td></tr>
    {find_rows}
  </table>

  <div class="foot">Last log line: {html.escape(last_status or "—")}<br>
    Auto-refreshes every {REFRESH_S}s · reads memory/program_watch_state.json + ~/.program_watch.log</div>
</div></body></html>"""


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        if self.path not in ("/", "/index.html"):
            self.send_response(404)
            self.end_headers()
            return
        try:
            body = render().encode("utf-8")
        except Exception as e:  # never let the dashboard 500 on bad data
            body = f"<pre>dashboard error: {html.escape(str(e))}</pre>".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):  # quiet
        pass


def main() -> int:
    ap = argparse.ArgumentParser(description="Local status page for the watcher.")
    ap.add_argument("--host", default="127.0.0.1",
                    help="Bind address (default localhost; 0.0.0.0 for LAN/phone).")
    ap.add_argument("--port", type=int, default=8787)
    args = ap.parse_args()
    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    where = f"http://{'127.0.0.1' if args.host in ('127.0.0.1', '0.0.0.0') else args.host}:{args.port}"
    print(f"[dashboard] serving on {where}  (bound {args.host}:{args.port})")
    print(f"[dashboard] reading {STATE_PATH} + {LOG_PATH}")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n[dashboard] stopped.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
