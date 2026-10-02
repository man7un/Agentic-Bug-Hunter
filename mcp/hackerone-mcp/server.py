#!/usr/bin/env python3
"""
HackerOne MCP Server — public endpoints only (no auth required).

Provides three tools:
  - search_disclosed_reports: Search Hacktivity for disclosed reports
  - get_program_stats: Bounty ranges, response times, resolved counts
  - get_program_policy: Safe harbor, response SLA, excluded vuln classes

This is a lightweight wrapper around HackerOne's public GraphQL API.
Authenticated endpoints (submit_report, private scope) are deferred.

Usage (standalone test):
    python3 mcp/hackerone-mcp/server.py search "ssrf" --limit 5
    python3 mcp/hackerone-mcp/server.py stats "example-corp"
    python3 mcp/hackerone-mcp/server.py policy "example-corp"

MCP integration:
    Add to .claude/settings.json mcpServers — see config.json.
"""

import json
import ssl
import sys
import urllib.request
import urllib.error
import urllib.parse
from datetime import datetime, timezone


# ─── SSL context ─────────────────────────────────────────────────────────────
_SSL_CTX = ssl.create_default_context()
try:
    import certifi
    _SSL_CTX = ssl.create_default_context(cafile=certifi.where())
except ImportError:
    _SSL_CTX.check_hostname = False
    _SSL_CTX.verify_mode = ssl.CERT_NONE

H1_GRAPHQL = "https://hackerone.com/graphql"
# HackerOne deprecated the public hacktivity GraphQL (hacktivity_items) in 2026;
# disclosed-report search now goes through the Hacker API, which serves the
# hacktivity feed unauthenticated as JSON:API.
H1_HACKTIVITY_API = "https://api.hackerone.com/v1/hackers/hacktivity"
DEFAULT_TIMEOUT = 15


class HackerOneAPIError(Exception):
    """Raised on API failures (rate limit, timeout, bad response)."""
    def __init__(self, message, status_code=None):
        super().__init__(message)
        self.status_code = status_code


def _graphql_request(query: str, timeout: int = DEFAULT_TIMEOUT) -> dict:
    """Execute a GraphQL request against HackerOne's public API."""
    payload = json.dumps({"query": query}).encode("utf-8")
    req = urllib.request.Request(
        H1_GRAPHQL,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "claude-bug-bounty/2.1",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_SSL_CTX) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            data = json.loads(body)
            if "errors" in data:
                raise HackerOneAPIError(
                    f"GraphQL errors: {data['errors']}",
                    status_code=200,
                )
            return data
    except urllib.error.HTTPError as e:
        raise HackerOneAPIError(
            f"HTTP {e.code}: {e.reason}",
            status_code=e.code,
        )
    except urllib.error.URLError as e:
        raise HackerOneAPIError(f"Network error: {e.reason}")
    except json.JSONDecodeError as e:
        raise HackerOneAPIError(f"Invalid JSON response: {e}")


# ─── Tool: search_disclosed_reports ──────────────────────────────────────────

def _hacktivity_api_get(query_string: str, limit: int,
                        sort: str = "-latest_disclosable_activity_at",
                        timeout: int = DEFAULT_TIMEOUT) -> dict:
    """GET the Hacker API hacktivity feed (JSON:API). Public, no auth."""
    params = urllib.parse.urlencode({
        "queryString": query_string,
        "page[size]": limit,
        "sort": sort,
    })
    url = f"{H1_HACKTIVITY_API}?{params}"
    req = urllib.request.Request(
        url,
        headers={"Accept": "application/json", "User-Agent": "claude-bug-bounty/2.1"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_SSL_CTX) as resp:
            return json.loads(resp.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as e:
        raise HackerOneAPIError(f"HTTP {e.code}: {e.reason}", status_code=e.code)
    except urllib.error.URLError as e:
        raise HackerOneAPIError(f"Network error: {e.reason}")
    except json.JSONDecodeError as e:
        raise HackerOneAPIError(f"Invalid JSON response: {e}")


def _norm_severity(value) -> str:
    """HackerOne returns severity as a word, the string 'None', or null."""
    if not value or str(value).lower() == "none":
        return "UNKNOWN"
    return str(value).upper()


def search_disclosed_reports(
    keyword: str = "",
    program: str = "",
    limit: int = 10,
) -> list[dict]:
    """Search HackerOne Hacktivity for disclosed reports.

    Uses the Hacker API hacktivity feed (the public GraphQL hacktivity_items
    query was deprecated by HackerOne in 2026). Return shape is unchanged.

    Args:
        keyword: Search term (vuln type, tech, etc.)
        program: HackerOne program handle (e.g. "shopify")
        limit: Max results (1-25)

    Returns:
        List of disclosed report summaries.
    """
    limit = max(1, min(25, limit))

    # Hacktivity query language: `disclosed:true`, `team_handle:<handle>`,
    # and free text. Keyword is quoted so spaces / reserved chars don't break
    # the query; the handle charset is safe unquoted.
    clauses = ["disclosed:true"]
    if keyword:
        clauses.append('"%s"' % keyword.replace('"', ""))
    if program:
        clauses.append("team_handle:%s" % program.replace('"', ""))
    query_string = " AND ".join(clauses)

    data = _hacktivity_api_get(query_string, limit)
    items = data.get("data") or []

    results = []
    for item in items:
        attrs = item.get("attributes") or {}
        if not attrs.get("disclosed_at"):
            continue  # defensive: skip anything not actually disclosed
        prog = (((item.get("relationships") or {}).get("program") or {})
                .get("data") or {}).get("attributes") or {}
        results.append({
            "title": attrs.get("title", "") or "",
            "severity": _norm_severity(attrs.get("severity_rating")),
            "disclosed_at": (attrs.get("disclosed_at") or "")[:10],
            "url": attrs.get("url", "") or "",
            "state": attrs.get("substate", "") or "",
            "program": prog.get("handle", ""),
            "program_name": prog.get("name", ""),
        })

    return results


# ─── Tool: get_program_stats ────────────────────────────────────────────────

def get_program_stats(program: str) -> dict:
    """Get public statistics for a HackerOne program.

    Args:
        program: HackerOne program handle (e.g. "shopify")

    Returns:
        Dict with bounty info, response times, resolved counts.
    """
    safe_program = program.replace('"', '\\"')
    query = f"""{{
      team(handle: "{safe_program}") {{
        name
        handle
        url
        offers_bounties
        default_currency
        base_bounty
        resolved_report_count
        average_time_to_bounty_awarded
        average_time_to_first_program_response
        launched_at
        state
      }}
    }}"""

    data = _graphql_request(query)
    team = (data.get("data") or {}).get("team")
    if not team:
        return {"error": f"Program '{program}' not found", "program": program}

    return {
        "program": team.get("handle", ""),
        "name": team.get("name", ""),
        "url": team.get("url", ""),
        "offers_bounties": team.get("offers_bounties", False),
        "currency": team.get("default_currency", "USD"),
        "base_bounty": team.get("base_bounty"),
        "resolved_reports": team.get("resolved_report_count"),
        "avg_days_to_bounty": team.get("average_time_to_bounty_awarded"),
        "avg_days_to_first_response": team.get("average_time_to_first_program_response"),
        "launched_at": (team.get("launched_at") or "")[:10],
        "state": team.get("state", ""),
    }


# ─── Tool: get_program_policy ────────────────────────────────────────────────

def get_program_policy(program: str) -> dict:
    """Get the public policy for a HackerOne program.

    Args:
        program: HackerOne program handle (e.g. "shopify")

    Returns:
        Dict with safe harbor status, response SLAs, excluded vuln classes.
    """
    safe_program = program.replace('"', '\\"')
    query = f"""{{
      team(handle: "{safe_program}") {{
        name
        handle
        policy
        offers_bounties
        structured_scopes(first: 50, archived: false) {{
          nodes {{
            asset_type
            asset_identifier
            eligible_for_bounty
            eligible_for_submission
            instruction
          }}
        }}
      }}
    }}"""

    data = _graphql_request(query)
    team = (data.get("data") or {}).get("team")
    if not team:
        return {"error": f"Program '{program}' not found", "program": program}

    scopes = []
    scope_nodes = (team.get("structured_scopes") or {}).get("nodes", [])
    for s in scope_nodes:
        scopes.append({
            "type": s.get("asset_type", ""),
            "identifier": s.get("asset_identifier", ""),
            "bounty_eligible": s.get("eligible_for_bounty", False),
            "submission_eligible": s.get("eligible_for_submission", True),
            "instruction": s.get("instruction", ""),
        })

    return {
        "program": team.get("handle", ""),
        "name": team.get("name", ""),
        "offers_bounties": team.get("offers_bounties", False),
        "policy_text": team.get("policy", ""),
        "scopes": scopes,
    }


# ─── CLI interface ───────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python3 server.py search <keyword> [--program <handle>] [--limit N]")
        print("  python3 server.py stats <program>")
        print("  python3 server.py policy <program>")
        sys.exit(1)

    cmd = sys.argv[1]

    try:
        if cmd == "search":
            keyword = sys.argv[2] if len(sys.argv) > 2 else ""
            program = ""
            limit = 10
            i = 3
            while i < len(sys.argv):
                if sys.argv[i] == "--program" and i + 1 < len(sys.argv):
                    program = sys.argv[i + 1]
                    i += 2
                elif sys.argv[i] == "--limit" and i + 1 < len(sys.argv):
                    limit = int(sys.argv[i + 1])
                    i += 2
                else:
                    i += 1
            results = search_disclosed_reports(keyword=keyword, program=program, limit=limit)
            print(json.dumps(results, indent=2))

        elif cmd == "stats":
            program = sys.argv[2] if len(sys.argv) > 2 else ""
            if not program:
                print("Error: program handle required")
                sys.exit(1)
            result = get_program_stats(program)
            print(json.dumps(result, indent=2))

        elif cmd == "policy":
            program = sys.argv[2] if len(sys.argv) > 2 else ""
            if not program:
                print("Error: program handle required")
                sys.exit(1)
            result = get_program_policy(program)
            print(json.dumps(result, indent=2))

        else:
            print(f"Unknown command: {cmd}")
            sys.exit(1)

    except HackerOneAPIError as e:
        print(json.dumps({"error": str(e), "status_code": e.status_code}))
        sys.exit(1)


if __name__ == "__main__":
    main()
