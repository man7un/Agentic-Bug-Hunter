#!/usr/bin/env python3
"""program_dossier.py — build a hunt dossier for a (newly detected) H1 program.

Given a HackerOne program handle, pulls the program's structured scope and a
sample of its disclosed reports from the PUBLIC GraphQL endpoint, heuristically
ranks the attack surface, suggests vuln classes to try, and writes a Markdown
dossier to findings/dossiers/<handle>-<date>.md.

This is the auto "scope + recon-seed + rank" stage that runs on detection. It is
deliberately PASSIVE — it reads HackerOne metadata only and fires NO active
traffic at the target. The in-scope asset list it produces is the seed for the
human-approved recon/hunt step (/recon, /autopilot), never a license to attack.

Usage:
    program_dossier.py <handle>              # build + write dossier, print path
    program_dossier.py <handle> --json       # emit the structured dossier as JSON
    program_dossier.py <handle> --stdout      # also print the markdown

Exit: 0 ok, 1 network/API error, 2 program not found. Stdlib only.
"""
from __future__ import annotations

import argparse
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

H1_GRAPHQL = "https://hackerone.com/graphql"
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOSSIER_DIR = os.path.join(BASE_DIR, "findings", "dossiers")
USER_AGENT = "claude-bug-bounty/program-dossier"

try:
    _SSL_CTX = ssl.create_default_context()
except Exception:  # pragma: no cover
    _SSL_CTX = None

# Heuristic weights for ranking in-scope assets by likely bug/bounty density.
_TYPE_SCORE = {
    "WILDCARD": 6, "URL": 5, "API": 6, "CIDR": 4, "SOURCE_CODE": 4,
    "DOWNLOADABLE_EXECUTABLES": 3, "GOOGLE_PLAY_APP_ID": 3, "APPLE_STORE_APP_ID": 3,
    "OTHER_APK": 3, "TESTFLIGHT": 3, "OTHER": 1,
}
# identifier keyword → (points, why)
_KEYWORD_SCORE = {
    "api": 3, "graphql": 3, "admin": 3, "auth": 3, "login": 2, "account": 2,
    "payment": 3, "billing": 2, "pay": 2, "oauth": 2, "sso": 2, "token": 2,
    "upload": 2, "file": 1, "internal": 2, "staging": 2, "stage": 2, "dev": 2,
    "test": 1, "beta": 1, "portal": 1, "dashboard": 2, "user": 1, "v1": 1, "v2": 1,
}
# asset signal → vuln classes worth trying first
_VULN_HINTS = [
    ("graphql", ["GraphQL introspection/authz", "IDOR via node IDs", "batching abuse"]),
    ("api", ["IDOR", "mass assignment", "JWT flaws", "broken object-level authz"]),
    ("auth", ["auth bypass", "OAuth/OIDC flaws", "MFA bypass"]),
    ("login", ["auth bypass", "account takeover chains", "credential handling"]),
    ("oauth", ["open-redirect→token theft", "OAuth misconfig"]),
    ("sso", ["SAML XSW / signature stripping", "SSO logic"]),
    ("upload", ["file upload bypass", "stored XSS via upload", "SSRF via parser"]),
    ("payment", ["business-logic / price tampering", "race conditions"]),
    ("admin", ["privilege escalation", "forced browsing", "IDOR to admin funcs"]),
]


def _graphql(query: str, timeout: int = 20) -> dict:
    payload = json.dumps({"query": query}).encode("utf-8")
    req = urllib.request.Request(
        H1_GRAPHQL, data=payload,
        headers={"Content-Type": "application/json", "User-Agent": USER_AGENT},
    )
    with urllib.request.urlopen(req, timeout=timeout, context=_SSL_CTX) as resp:
        data = json.loads(resp.read().decode("utf-8", errors="replace"))
    if "errors" in data:
        raise RuntimeError(f"GraphQL errors: {data['errors']}")
    return data


YWH_PROGRAM_API = "https://api.yeswehack.com/programs"
# YesWeHack scope_type → an H1-style bucket so _TYPE_SCORE applies uniformly.
_YWH_TYPE = {
    "api": "API", "web-application": "URL", "ip-address": "CIDR",
    "source-code": "SOURCE_CODE", "executable": "DOWNLOADABLE_EXECUTABLES",
    "mobile-application": "OTHER_APK", "mobile-application-android": "GOOGLE_PLAY_APP_ID",
    "mobile-application-ios": "APPLE_STORE_APP_ID", "android-application": "GOOGLE_PLAY_APP_ID",
    "ios-application": "APPLE_STORE_APP_ID",
}
# YesWeHack publishes a per-asset criticality — fold it straight into the rank.
_YWH_PRIORITY = {"CRITICAL": 5, "HIGH": 3, "MEDIUM": 1, "LOW": 0, "NONE": 0}


def _get_json(url: str, timeout: int = 20) -> dict:
    req = urllib.request.Request(
        url, headers={"Accept": "application/json", "User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout, context=_SSL_CTX) as resp:
        return json.loads(resp.read().decode("utf-8", errors="replace"))


def fetch_policy_h1(handle: str) -> dict | None:
    """HackerOne policy + structured scope, or None if the program isn't found."""
    safe = handle.replace('"', '\\"')
    query = (
        '{ team(handle: "%s") { name handle offers_bounties url policy '
        'structured_scopes(first: 100, archived: false) { nodes { '
        'asset_type asset_identifier eligible_for_bounty eligible_for_submission '
        'instruction } } } }' % safe
    )
    try:
        team = (_graphql(query).get("data") or {}).get("team")
    except RuntimeError as e:
        # A missing/renamed program comes back as a NOT_FOUND GraphQL error, not
        # team=null — treat that as "not found" (exit 2), not a network failure.
        if "NOT_FOUND" in str(e) or "does not exist" in str(e):
            return None
        raise
    if not team:
        return None
    scopes = [
        {
            "type": s.get("asset_type", ""),
            "identifier": s.get("asset_identifier", ""),
            "bounty": bool(s.get("eligible_for_bounty")),
            "submit": s.get("eligible_for_submission", True),
            "instruction": (s.get("instruction") or "").strip(),
            "priority": 0, "priority_label": "",
        }
        for s in ((team.get("structured_scopes") or {}).get("nodes") or [])
    ]
    return {
        "source": "h1",
        "platform": "HackerOne",
        "handle": team.get("handle", handle),
        "name": team.get("name", handle),
        "offers_bounties": bool(team.get("offers_bounties")),
        "url": team.get("url") or f"https://hackerone.com/{handle}",
        "policy_text": team.get("policy") or "",
        "scopes": scopes,
        "out_of_scope_notes": [],   # H1 encodes this via non-submittable scopes
        "reward_range": "",
        "qualifying": [],
    }


def fetch_policy_ywh(slug: str) -> dict | None:
    """YesWeHack program detail + scope, or None if not found/unavailable."""
    try:
        d = _get_json(f"{YWH_PROGRAM_API}/{urllib.parse.quote(slug)}")
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise
    if not d or d.get("disabled") or d.get("archived"):
        return None
    pays = bool(d.get("bounty"))
    scopes = []
    for s in d.get("scopes", []):
        ident = (s.get("scope") or "").strip()
        if not ident:
            continue
        stype = (s.get("scope_type") or "").lower()
        crit = (s.get("asset_value") or "").upper()
        scopes.append({
            "type": _YWH_TYPE.get(stype, "OTHER"),
            "identifier": ident,
            "bounty": pays,              # in-scope assets are bounty-eligible if the program pays
            "submit": True,              # listed in-scope = submittable
            "instruction": s.get("scope_type_name") or stype,
            "priority": _YWH_PRIORITY.get(crit, 0),
            "priority_label": crit,
        })
    oos = d.get("out_of_scope")
    oos_notes = [str(x) for x in oos] if isinstance(oos, list) else ([str(oos)] if oos else [])
    rmin, rmax = d.get("bounty_reward_min"), d.get("bounty_reward_max")
    reward_range = f"${rmin}–${rmax}" if (rmin or rmax) else ""
    qualifying = []
    qv = d.get("qualifying_vulnerability")
    if isinstance(qv, str) and qv.strip():
        qualifying = [ln.strip("-* \t") for ln in qv.splitlines() if ln.strip()][:12]
    return {
        "source": "ywh",
        "platform": "YesWeHack",
        "handle": d.get("slug", slug),
        "name": d.get("title", slug),
        "offers_bounties": pays,
        "url": f"https://yeswehack.com/programs/{d.get('slug', slug)}",
        "policy_text": d.get("rules") or "",
        "scopes": scopes,
        "out_of_scope_notes": oos_notes,
        "reward_range": reward_range,
        "qualifying": qualifying,
    }


def fetch_disclosed(handle: str, limit: int = 8) -> list[dict]:
    """Recent disclosed reports for the program (intel on what pays here).

    Uses the Hacker API hacktivity feed (JSON:API, public/no-auth) — the public
    GraphQL hacktivity_items query was deprecated by HackerOne in 2026. Still
    best-effort: any failure degrades to an empty list, not a broken dossier.
    """
    params = urllib.parse.urlencode({
        "queryString": f"disclosed:true AND team_handle:{handle}",
        "page[size]": limit,
        "sort": "-latest_disclosable_activity_at",
    })
    url = f"https://api.hackerone.com/v1/hackers/hacktivity?{params}"
    req = urllib.request.Request(
        url, headers={"Accept": "application/json", "User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=20, context=_SSL_CTX) as resp:
            items = (json.loads(resp.read().decode("utf-8", errors="replace"))
                     .get("data") or [])
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError,
            json.JSONDecodeError):
        return []
    out = []
    for it in items:
        a = (it or {}).get("attributes") or {}
        if not a.get("title") or not a.get("disclosed_at"):
            continue
        sev = a.get("severity_rating")
        out.append({
            "title": a.get("title", ""),
            "severity": "n/a" if not sev or str(sev).lower() == "none" else sev,
            "awarded": a.get("total_awarded_amount"),
        })
    return out


def rank_assets(scopes: list[dict]) -> list[dict]:
    """Score submittable assets by likely bug/bounty density, highest first."""
    ranked = []
    for s in scopes:
        if not s["submit"]:
            continue  # can't submit against it → not a hunt target
        score = _TYPE_SCORE.get(s["type"], 1)
        if s["bounty"]:
            score += 3
        reasons = []
        # Platform-published criticality (YesWeHack asset_value) folds straight in.
        prio = s.get("priority", 0)
        if prio:
            score += prio
            reasons.append(s.get("priority_label", "").lower() or f"prio+{prio}")
        ident = s["identifier"].lower()
        for kw, pts in _KEYWORD_SCORE.items():
            if kw in ident:
                score += pts
                reasons.append(kw)
        ranked.append({**s, "score": score, "signals": reasons})
    ranked.sort(key=lambda a: a["score"], reverse=True)
    return ranked


def suggest_vuln_classes(ranked: list[dict]) -> list[str]:
    haystack = " ".join(f"{a['type']} {a['identifier']}".lower() for a in ranked)
    picks: list[str] = []
    for sig, classes in _VULN_HINTS:
        if sig in haystack:
            for c in classes:
                if c not in picks:
                    picks.append(c)
    if not picks:  # generic web surface
        picks = ["IDOR", "auth bypass", "business logic", "XSS", "SSRF"]
    return picks


def build_markdown(pol: dict, ranked: list[dict], disclosed: list[dict],
                   vulns: list[str]) -> str:
    today = time.strftime("%Y-%m-%d", time.gmtime())
    bounty = "💰 pays bounties" if pol["offers_bounties"] else "VDP (reputation only)"
    L = [
        f"# Hunt Dossier — {pol['name']} (`{pol['handle']}`)",
        "",
        f"- **Platform:** {pol.get('platform', pol['source'])}",
        f"- **Program:** {pol['url']}",
        f"- **Type:** {bounty}",
        f"- **Generated:** {today} (auto — passive scope+intel only, no active traffic sent)",
        "",
        "## In-scope attack surface (ranked)",
        "",
        "Score = asset-type weight + bounty-eligible + identifier signals. "
        "Hunt top-down. This is a *seed list* — recon/testing is the approved next step.",
        "",
        "| # | Score | Type | Asset | Bounty | Signals |",
        "|---|------:|------|-------|:------:|---------|",
    ]
    if ranked:
        for i, a in enumerate(ranked[:25], 1):
            sig = ", ".join(a["signals"]) or "—"
            L.append(f"| {i} | {a['score']} | {a['type']} | `{a['identifier']}` | "
                     f"{'✅' if a['bounty'] else '—'} | {sig} |")
    else:
        L.append("| — | — | — | _no submittable structured scope published_ | — | — |")

    # Out of scope: H1 encodes it as non-submittable structured scopes; YWH
    # publishes free-text notes.
    if pol.get("out_of_scope_notes"):
        L += ["", "## Out of scope (program notes — skip these)", ""]
        for note in pol["out_of_scope_notes"][:20]:
            L.append(f"- {note}")
    else:
        out_of_scope = [s for s in pol["scopes"] if not s["submit"]]
        if out_of_scope:
            L += ["", "## Explicitly NOT submittable (skip these)", ""]
            for s in out_of_scope:
                L.append(f"- `{s['identifier']}` ({s['type']})")

    L += ["", "## Suggested vuln classes (first passes)", ""]
    L += [f"- {c}" for c in vulns]

    # Intel: H1 pulls disclosed reports via the Hacker API; YWH surfaces its
    # published reward range + qualifying-vuln list from the program detail.
    if pol["source"] == "ywh":
        L += ["", "## Intel — program economics & qualifying vulns", ""]
        if pol.get("reward_range"):
            L.append(f"- Bounty range: **{pol['reward_range']}**")
        if pol.get("qualifying"):
            L.append("- Qualifying vulnerabilities (per program):")
            L += [f"    - {q}" for q in pol["qualifying"]]
        if not pol.get("reward_range") and not pol.get("qualifying"):
            L.append(f"- See the program page for reward grid / rules: {pol['url']}")
    else:
        L += ["", "## Intel — recent disclosed reports on this program", ""]
        if disclosed:
            for d in disclosed:
                amt = f" — ${d['awarded']}" if d.get("awarded") else ""
                L.append(f"- [{d['severity']}] {d['title']}{amt}")
        else:
            L += [
                "- _No public disclosure intel fetched — HackerOne deprecated the free "
                "hacktivity GraphQL (now behind the authenticated Hacker API)._",
                f"- Browse disclosed reports manually: {pol['url']}/hacktivity",
            ]

    top_target = ranked[0]["identifier"] if ranked else "<in-scope-asset>"
    L += [
        "", "## Next steps (human-approved)", "",
        f"1. `/scope {top_target}` — confirm it resolves to the program's assets.",
        f"2. `/recon {top_target}` — enumerate the real surface.",
        f"3. `/autopilot {top_target} --normal` — bounded, scope-checked hunt "
        "(human-gated submission).",
        "",
        "_Read the full policy before any active testing:_ " + pol["url"],
        "",
    ]
    if pol["policy_text"]:
        snippet = pol["policy_text"].strip()
        if len(snippet) > 1500:
            snippet = snippet[:1500] + "\n\n…(truncated — read full policy at the link above)"
        L += ["<details><summary>Policy text (excerpt)</summary>", "", "```",
              snippet, "```", "</details>", ""]
    return "\n".join(L)


def write_dossier(handle: str, markdown: str) -> str:
    os.makedirs(DOSSIER_DIR, exist_ok=True)
    path = os.path.join(DOSSIER_DIR, f"{handle}-{time.strftime('%Y%m%d', time.gmtime())}.md")
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(markdown)
    os.replace(tmp, path)
    return path


def main() -> int:
    ap = argparse.ArgumentParser(description="Build a hunt dossier for a program.")
    ap.add_argument("handle", help="Program handle/slug (HackerOne handle, or YWH slug).")
    ap.add_argument("--source", default="h1", choices=["h1", "ywh"],
                    help="Platform the handle belongs to (default: h1).")
    ap.add_argument("--json", action="store_true", help="Emit structured JSON.")
    ap.add_argument("--stdout", action="store_true", help="Also print the markdown.")
    args = ap.parse_args()

    fetcher = fetch_policy_h1 if args.source == "h1" else fetch_policy_ywh
    try:
        pol = fetcher(args.handle)
    except (urllib.error.URLError, urllib.error.HTTPError, RuntimeError, TimeoutError) as e:
        print(f"[dossier] API error for '{args.handle}' ({args.source}): {e}", file=sys.stderr)
        return 1
    if pol is None:
        print(f"[dossier] program '{args.handle}' not found on {args.source}.", file=sys.stderr)
        return 2

    ranked = rank_assets(pol["scopes"])
    disclosed = fetch_disclosed(args.handle) if args.source == "h1" else []
    vulns = suggest_vuln_classes(ranked)
    markdown = build_markdown(pol, ranked, disclosed, vulns)
    path = write_dossier(args.handle, markdown)

    if args.json:
        print(json.dumps({
            "handle": pol["handle"], "name": pol["name"],
            "offers_bounties": pol["offers_bounties"], "url": pol["url"],
            "ranked": ranked, "disclosed": disclosed,
            "suggested_vuln_classes": vulns, "dossier_path": path,
        }, indent=2))
    elif args.stdout:
        print(markdown)
        print(f"\n[dossier] written → {path}")
    else:
        top = ranked[0]["identifier"] if ranked else "(no submittable scope)"
        print(f"[dossier] {pol['name']} [{pol['handle']}] — "
              f"{len(ranked)} ranked assets, top: {top}")
        print(path)  # last line = path, for callers to capture
    return 0


if __name__ == "__main__":
    sys.exit(main())
