"""Tests for mcp/hackerone-mcp/server.py — HackerOne MCP server tools."""

import json
import pytest
from unittest.mock import patch, MagicMock
from urllib.error import HTTPError, URLError
from io import BytesIO

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "mcp", "hackerone-mcp"))

from server import (
    search_disclosed_reports,
    get_program_stats,
    get_program_policy,
    HackerOneAPIError,
    _graphql_request,
)


class TestGraphQLRequest:

    @patch("server.urllib.request.urlopen")
    def test_success(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({"data": {"ok": True}}).encode()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        result = _graphql_request("{ test }")
        assert result["data"]["ok"] is True

    @patch("server.urllib.request.urlopen")
    def test_graphql_errors_raise(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({
            "errors": [{"message": "field not found"}]
        }).encode()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        with pytest.raises(HackerOneAPIError, match="GraphQL errors"):
            _graphql_request("{ bad_query }")

    @patch("server.urllib.request.urlopen")
    def test_http_error(self, mock_urlopen):
        mock_urlopen.side_effect = HTTPError(
            url="https://hackerone.com/graphql",
            code=429, msg="Too Many Requests",
            hdrs={}, fp=BytesIO(b""),
        )
        with pytest.raises(HackerOneAPIError) as exc_info:
            _graphql_request("{ test }")
        assert exc_info.value.status_code == 429

    @patch("server.urllib.request.urlopen")
    def test_network_error(self, mock_urlopen):
        mock_urlopen.side_effect = URLError("timed out")
        with pytest.raises(HackerOneAPIError, match="Network error"):
            _graphql_request("{ test }")


class TestSearchDisclosedReports:

    @patch("server._hacktivity_api_get")
    def test_returns_reports(self, mock_api):
        # Hacker API JSON:API shape.
        mock_api.return_value = {
            "data": [
                {
                    "id": 99999,
                    "type": "hacktivity_item",
                    "attributes": {
                        "title": "SSRF via webhook URL",
                        "severity_rating": "critical",
                        "disclosed_at": "2026-02-10T00:00:00Z",
                        "url": "https://hackerone.com/reports/99999",
                        "substate": "resolved",
                    },
                    "relationships": {
                        "program": {"data": {"attributes": {
                            "handle": "acme", "name": "Acme Corp",
                        }}}
                    },
                }
            ]
        }

        results = search_disclosed_reports(keyword="ssrf")
        assert len(results) == 1
        assert results[0]["title"] == "SSRF via webhook URL"
        assert results[0]["severity"] == "CRITICAL"
        assert results[0]["program"] == "acme"
        assert results[0]["program_name"] == "Acme Corp"

    @patch("server._hacktivity_api_get")
    def test_severity_none_normalized(self, mock_api):
        # HackerOne sends severity as the string "None" or null for some items.
        mock_api.return_value = {"data": [{
            "attributes": {
                "title": "Informative finding",
                "severity_rating": "None",
                "disclosed_at": "2026-02-10T00:00:00Z",
                "url": "https://hackerone.com/reports/1",
                "substate": "informative",
            },
            "relationships": {},
        }]}
        results = search_disclosed_reports(keyword="x")
        assert results[0]["severity"] == "UNKNOWN"
        assert results[0]["program"] == ""  # missing relationship → empty, no crash

    @patch("server._hacktivity_api_get")
    def test_empty_results(self, mock_api):
        mock_api.return_value = {"data": []}
        results = search_disclosed_reports(keyword="nonexistent")
        assert results == []

    @patch("server._hacktivity_api_get")
    def test_program_filter(self, mock_api):
        mock_api.return_value = {"data": []}
        search_disclosed_reports(program="shopify", limit=5)
        query_string = mock_api.call_args[0][0]
        assert "team_handle:shopify" in query_string
        assert "disclosed:true" in query_string

    def test_limit_clamped(self):
        # limit is clamped in the function, verify no crash
        with patch("server._hacktivity_api_get") as mock_api:
            mock_api.return_value = {"data": []}
            search_disclosed_reports(keyword="test", limit=100)
            search_disclosed_reports(keyword="test", limit=-5)
            # clamped into [1, 25]
            assert mock_api.call_args_list[0][0][1] == 25
            assert mock_api.call_args_list[1][0][1] == 1

    @patch("server._hacktivity_api_get")
    def test_skips_non_disclosed_items(self, mock_api):
        # Feed mixes undisclosed items (null disclosed_at) with disclosed ones.
        mock_api.return_value = {"data": [
            {"attributes": {"title": None, "disclosed_at": None}, "relationships": {}},
            {
                "attributes": {"title": "Valid", "severity_rating": "low",
                               "disclosed_at": "2026-01-01", "url": "https://h1.com/1",
                               "substate": "resolved"},
                "relationships": {"program": {"data": {"attributes": {
                    "handle": "test", "name": "Test"}}}},
            },
        ]}
        results = search_disclosed_reports(keyword="test")
        assert len(results) == 1
        assert results[0]["title"] == "Valid"


class TestGetProgramStats:

    @patch("server._graphql_request")
    def test_returns_stats(self, mock_gql):
        mock_gql.return_value = {
            "data": {
                "team": {
                    "name": "Acme Corp",
                    "handle": "acme",
                    "url": "https://hackerone.com/acme",
                    "offers_bounties": True,
                    "default_currency": "USD",
                    "base_bounty": 500,
                    "resolved_report_count": 100,
                    "average_time_to_bounty_awarded": 14,
                    "average_time_to_first_program_response": 2,
                    "launched_at": "2020-01-01T00:00:00Z",
                    "state": "public_mode",
                }
            }
        }

        stats = get_program_stats("acme")
        assert stats["program"] == "acme"
        assert stats["offers_bounties"] is True
        assert stats["base_bounty"] == 500
        assert stats["resolved_reports"] == 100

    @patch("server._graphql_request")
    def test_program_not_found(self, mock_gql):
        mock_gql.return_value = {"data": {"team": None}}
        stats = get_program_stats("nonexistent")
        assert "error" in stats


class TestGetProgramPolicy:

    @patch("server._graphql_request")
    def test_returns_policy_with_scopes(self, mock_gql):
        mock_gql.return_value = {
            "data": {
                "team": {
                    "name": "Acme Corp",
                    "handle": "acme",
                    "policy": "Do not test staging.",
                    "offers_bounties": True,
                    "structured_scopes": {
                        "nodes": [
                            {
                                "asset_type": "URL",
                                "asset_identifier": "*.acme.com",
                                "eligible_for_bounty": True,
                                "eligible_for_submission": True,
                                "instruction": "Main domain",
                            },
                            {
                                "asset_type": "URL",
                                "asset_identifier": "staging.acme.com",
                                "eligible_for_bounty": False,
                                "eligible_for_submission": False,
                                "instruction": "Out of scope",
                            },
                        ]
                    },
                }
            }
        }

        policy = get_program_policy("acme")
        assert policy["program"] == "acme"
        assert "Do not test staging" in policy["policy_text"]
        assert len(policy["scopes"]) == 2
        assert policy["scopes"][0]["bounty_eligible"] is True
        assert policy["scopes"][1]["bounty_eligible"] is False

    @patch("server._graphql_request")
    def test_program_not_found(self, mock_gql):
        mock_gql.return_value = {"data": {"team": None}}
        policy = get_program_policy("ghost")
        assert "error" in policy
