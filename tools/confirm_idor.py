#!/usr/bin/env python3
"""
confirm_idor.py — CONFIRMS cross-account IDOR with a mechanical response diff.

The rest of the toolkit is confirmation-poor here too: "I got a 200 OK requesting
someone else's ID" is not proof — plenty of endpoints return 200 with generic or
self-scoped data regardless of the ID in the URL. This independently re-fires the
request as the attacker against the victim's resource and requires a literal
victim-specific marker (an email, username, order number — something that can only
be there if the *victim's* data came back) to actually appear in the body before
calling it CONFIRMED.

This does NOT decide whether IDOR is exploitable in the abstract — it decides
whether *this specific request, right now, with these credentials* returns
*this specific victim's data* to someone who shouldn't have it. That is the bar
Q1/Q6 of the validator ask for.

Usage:
  tools/confirm_idor.py URL --attacker-header "Authorization: Bearer eyJ..." \\
      --victim-marker "victim@example.com"

  tools/confirm_idor.py URL --attacker-cookie "session=abc123" \\
      --victim-marker "ORD-88213" --proof findings/target-idor/proof.json

  # Stronger check: also confirm the attacker's OWN request to their own resource
  # does NOT contain the victim marker (rules out an endpoint that just always
  # echoes that string back regardless of auth).
  tools/confirm_idor.py URL --attacker-header "Authorization: Bearer eyJ..." \\
      --victim-marker "victim@example.com" --control-url "https://.../resource/OWN_ID"
"""
from __future__ import annotations

import argparse
import sys
import urllib.error
import urllib.request

from confirm_common import CONFIRMED, POSSIBLE, UNCONFIRMED, Proof, write_proof

USER_AGENT = "claude-bug-bounty/confirm_idor"


def _headers_from_args(header: list[str] | None, cookie: str | None) -> dict:
    headers = {"User-Agent": USER_AGENT}
    for h in header or []:
        if ":" not in h:
            raise ValueError(f"--attacker-header must be 'Name: value', got {h!r}")
        name, _, value = h.partition(":")
        headers[name.strip()] = value.strip()
    if cookie:
        headers["Cookie"] = cookie
    return headers


def fetch(url: str, headers: dict, timeout: int = 15) -> tuple[int, str]:
    """Not pure — makes the actual request. Kept tiny and separate so classify()
    below stays pure and unit-testable without any network access."""
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            return resp.status, body
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", errors="replace")


def classify(
    status: int,
    body: str,
    victim_marker: str,
    control_body: str | None,
) -> tuple[str, str]:
    """Pure: decide CONFIRMED / POSSIBLE / UNCONFIRMED from response data alone.

    CONFIRMED   — victim marker present in the attacker's response, AND (if a
                  control request was supplied) absent from the attacker's own
                  resource — ruling out an endpoint that echoes it unconditionally.
    POSSIBLE    — victim marker present but a control request ALSO contains it,
                  meaning the marker doesn't actually discriminate between
                  resources — this is not proof of cross-account access.
    UNCONFIRMED — victim marker never showed up; the request didn't return their data.
    """
    if status >= 400:
        return UNCONFIRMED, f"request failed with HTTP {status}, no data returned"

    marker_present = victim_marker in body
    if not marker_present:
        return UNCONFIRMED, f"HTTP {status} but victim marker {victim_marker!r} not in response body"

    if control_body is not None and victim_marker in control_body:
        return POSSIBLE, (
            f"victim marker {victim_marker!r} present, but it ALSO appears in the "
            f"control response (attacker's own resource) — marker does not "
            f"discriminate between accounts, this does not prove cross-account access"
        )

    return CONFIRMED, f"HTTP {status}, victim marker {victim_marker!r} present in attacker's response{' (absent from control)' if control_body is not None else ''}"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Confirm cross-account IDOR with a mechanical response diff.")
    ap.add_argument("url", help="the victim's resource URL, requested with the attacker's credentials")
    ap.add_argument("--attacker-header", action="append", default=[],
                     help="'Name: value' header for the attacker's session (repeatable)")
    ap.add_argument("--attacker-cookie", default=None, help="Cookie header value for the attacker's session")
    ap.add_argument("--victim-marker", required=True,
                     help="a literal string that can only appear if the VICTIM's data came back "
                          "(their email, order ID, username — something unique to them)")
    ap.add_argument("--control-url", default=None,
                     help="attacker's own equivalent resource, to rule out the marker being echoed "
                          "unconditionally (recommended)")
    ap.add_argument("--proof", default=None, help="write a proof.json artifact here")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    try:
        headers = _headers_from_args(args.attacker_header, args.attacker_cookie)
    except ValueError as exc:
        print(f"[-] {exc}", file=sys.stderr)
        return 2

    status, body = fetch(args.url, headers)
    control_body = None
    if args.control_url:
        _, control_body = fetch(args.control_url, headers)

    verdict, reason = classify(status, body, args.victim_marker, control_body)

    proof = Proof(
        tool="confirm_idor.py",
        vuln_class="idor",
        target_url=args.url,
        verdict=verdict,
        evidence={
            "status": status,
            "victim_marker": args.victim_marker,
            "control_url": args.control_url,
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
