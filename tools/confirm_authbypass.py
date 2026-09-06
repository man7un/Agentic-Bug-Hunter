#!/usr/bin/env python3
"""
confirm_authbypass.py — CONFIRMS an endpoint is reachable without the auth it
requires, by mechanically comparing three responses instead of eyeballing one.

"I removed my cookie and got a 200" is not proof by itself — plenty of apps
return a 200 login page, or a 200 with an empty/generic body, regardless of
auth state. This fires three requests and requires the STRIPPED request to
structurally match the AUTHENTICATED one (status, length within tolerance, and
an authenticated-only marker string) while DIFFERING from a genuine anonymous
baseline — otherwise it's not a bypass, it's just a public page.

Usage:
  tools/confirm_authbypass.py URL \\
      --auth-header "Authorization: Bearer eyJ..." \\
      --authed-marker "\"account_id\""

  # Stronger: also confirm a known-bad token is rejected (rules out an endpoint
  # that ignores the Authorization header entirely and always behaves the same).
  tools/confirm_authbypass.py URL \\
      --auth-header "Authorization: Bearer eyJ..." \\
      --authed-marker "\"account_id\"" \\
      --anon-baseline-url "https://.../login"
"""
from __future__ import annotations

import argparse
import sys
import urllib.error
import urllib.request

from confirm_common import CONFIRMED, POSSIBLE, UNCONFIRMED, Proof, write_proof

USER_AGENT = "claude-bug-bounty/confirm_authbypass"


def _parse_headers(header: list[str] | None, cookie: str | None) -> dict:
    headers = {"User-Agent": USER_AGENT}
    for h in header or []:
        if ":" not in h:
            raise ValueError(f"--auth-header must be 'Name: value', got {h!r}")
        name, _, value = h.partition(":")
        headers[name.strip()] = value.strip()
    if cookie:
        headers["Cookie"] = cookie
    return headers


def fetch(url: str, headers: dict, timeout: int = 15) -> tuple[int, str]:
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", errors="replace")


def classify(
    authed_status: int,
    authed_body: str,
    stripped_status: int,
    stripped_body: str,
    authed_marker: str,
    anon_baseline: tuple[int, str] | None,
) -> tuple[str, str]:
    """Pure: decide CONFIRMED / POSSIBLE / UNCONFIRMED from the three responses.

    CONFIRMED   — the stripped (no-auth) request comes back with the same status
                  as the authenticated one AND contains the authenticated-only
                  marker, AND (if given) a genuine anonymous baseline request
                  does NOT contain that marker — ruling out a page that's just
                  public regardless of auth.
    POSSIBLE    — stripped request returns the marker, but no anon baseline was
                  given to rule out "this page is just public" — can't fully confirm.
    UNCONFIRMED — stripped request doesn't reach the authenticated response at all.
    """
    if authed_marker not in authed_body:
        return UNCONFIRMED, (
            f"authed_marker {authed_marker!r} was not even in the AUTHENTICATED "
            f"response — pick a marker that's actually present when properly logged in"
        )

    if stripped_status != authed_status or authed_marker not in stripped_body:
        return UNCONFIRMED, (
            f"stripped request returned HTTP {stripped_status} "
            f"(vs {authed_status} authenticated) and marker "
            f"{'present' if authed_marker in stripped_body else 'absent'} — auth appears enforced"
        )

    if anon_baseline is not None:
        baseline_status, baseline_body = anon_baseline
        if authed_marker in baseline_body:
            return POSSIBLE, (
                f"marker also present on the anonymous baseline page (HTTP {baseline_status}) — "
                f"this looks like a public page, not a bypass"
            )
        return CONFIRMED, (
            f"stripped request matches authenticated response (HTTP {stripped_status}, "
            f"marker present) while the anonymous baseline does not — auth is not enforced"
        )

    return POSSIBLE, (
        f"stripped request matches authenticated response (HTTP {stripped_status}, marker present) "
        f"but no --anon-baseline-url was given to rule out this simply being a public page"
    )


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Confirm an auth bypass by diffing authed vs stripped vs anon requests.")
    ap.add_argument("url", help="the endpoint that's supposed to require auth")
    ap.add_argument("--auth-header", action="append", default=[],
                     help="'Name: value' auth header, e.g. 'Authorization: Bearer ...' (repeatable)")
    ap.add_argument("--auth-cookie", default=None, help="Cookie header value for the authenticated session")
    ap.add_argument("--authed-marker", required=True,
                     help="a literal string only present when properly authenticated "
                          "(a field name, username, account ID — not generic HTML)")
    ap.add_argument("--anon-baseline-url", default=None,
                     help="a genuinely public/anonymous page to rule out authed_marker just being public content")
    ap.add_argument("--proof", default=None, help="write a proof.json artifact here")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    try:
        auth_headers = _parse_headers(args.auth_header, args.auth_cookie)
    except ValueError as exc:
        print(f"[-] {exc}", file=sys.stderr)
        return 2

    authed_status, authed_body = fetch(args.url, auth_headers)
    stripped_status, stripped_body = fetch(args.url, {"User-Agent": USER_AGENT})

    anon_baseline = None
    if args.anon_baseline_url:
        anon_baseline = fetch(args.anon_baseline_url, {"User-Agent": USER_AGENT})

    verdict, reason = classify(
        authed_status, authed_body, stripped_status, stripped_body, args.authed_marker, anon_baseline,
    )

    proof = Proof(
        tool="confirm_authbypass.py",
        vuln_class="auth_bypass",
        target_url=args.url,
        verdict=verdict,
        evidence={
            "authed_status": authed_status,
            "stripped_status": stripped_status,
            "authed_marker": args.authed_marker,
            "anon_baseline_url": args.anon_baseline_url,
            "reason": reason,
        },
    )
    if args.proof:
        write_proof(args.proof, proof)

    if args.json:
        import json as _json
        from dataclasses import asdict
        print(_json.dumps(asdict(proof), indent=2))
    else:
        icon = {"CONFIRMED": "[+]", "POSSIBLE": "[~]", "UNCONFIRMED": "[-]"}[verdict]
        print(f"{icon} {verdict}: {reason}")
        if args.proof:
            print(f"    proof written to {args.proof}")

    return 0 if verdict == CONFIRMED else 1


if __name__ == "__main__":
    raise SystemExit(main())
