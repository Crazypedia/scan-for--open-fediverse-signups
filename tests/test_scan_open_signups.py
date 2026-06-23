import pytest
import aiohttp
import json
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

# Fix import issue since the file has .py in the name and is in root
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import importlib
scan_module = importlib.import_module("scan_open_signups")

_safe_read_json = scan_module._safe_read_json
fetch_known_peers = scan_module.fetch_known_peers
_check_v2_instance = scan_module._check_v2_instance
_check_v1_instance = scan_module._check_v1_instance
check_server = scan_module.check_server
MAX_RESPONSE_BYTES = scan_module.MAX_RESPONSE_BYTES

@pytest.mark.asyncio
async def test_safe_read_json_valid():
    mock_resp = MagicMock(spec=aiohttp.ClientResponse)
    mock_resp.headers = {"Content-Length": "100"}
    mock_resp.read.return_value = b'{"key": "value"}'

    result = await _safe_read_json(mock_resp)
    assert result == {"key": "value"}

@pytest.mark.asyncio
async def test_safe_read_json_oversized_header():
    mock_resp = MagicMock(spec=aiohttp.ClientResponse)
    mock_resp.headers = {"Content-Length": str(MAX_RESPONSE_BYTES + 1)}

    result = await _safe_read_json(mock_resp)
    assert result is None

@pytest.mark.asyncio
async def test_safe_read_json_oversized_body():
    mock_resp = MagicMock(spec=aiohttp.ClientResponse)
    mock_resp.headers = {}
    mock_resp.read.return_value = b" " * (MAX_RESPONSE_BYTES + 1)

    result = await _safe_read_json(mock_resp)
    assert result is None

@pytest.mark.asyncio
async def test_safe_read_json_invalid():
    mock_resp = MagicMock(spec=aiohttp.ClientResponse)
    mock_resp.headers = {}
    mock_resp.read.return_value = b"invalid json"

    result = await _safe_read_json(mock_resp)
    assert result is None

def test_fetch_known_peers_success():
    with patch("scan_open_signups.Mastodon") as mock_mastodon:
        instance = mock_mastodon.return_value
        instance.instance_peers.return_value = ["valid.com", "INVALID_DOMAIN", 123, "  another.com  "]

        peers = fetch_known_peers("https://home.com", "token")
        assert peers == ["valid.com", "another.com"]

def test_fetch_known_peers_error():
    with patch("scan_open_signups.Mastodon") as mock_mastodon:
        instance = mock_mastodon.return_value
        instance.instance_peers.side_effect = Exception("API Error")

        peers = fetch_known_peers("https://home.com", "token")
        assert peers == []

@pytest.mark.asyncio
async def test_check_v2_instance_open():
    domain = "open.social"
    with patch("aiohttp.ClientSession.get") as mock_get:
        mock_resp = MagicMock(spec=aiohttp.ClientResponse)
        mock_resp.status = 200
        mock_resp.headers = {}
        async def mock_read():
            return b'{"registrations": {"enabled": true, "approval_required": false}}'
        mock_resp.read = mock_read

        mock_get.return_value.__aenter__.return_value = mock_resp

        async with aiohttp.ClientSession() as session:
            timeout = aiohttp.ClientTimeout(total=5)
            result = await _check_v2_instance(session, domain, timeout)
            assert result["open_signup"] is True
            assert result["registration_mode"] == "open"

@pytest.mark.asyncio
async def test_check_v1_instance_approval():
    domain = "approval.social"
    with patch("aiohttp.ClientSession.get") as mock_get:
        mock_resp = MagicMock(spec=aiohttp.ClientResponse)
        mock_resp.status = 200
        mock_resp.headers = {}
        async def mock_read():
            return b'{"registrations": true, "approval_required": true}'
        mock_resp.read = mock_read

        mock_get.return_value.__aenter__.return_value = mock_resp

        async with aiohttp.ClientSession() as session:
            timeout = aiohttp.ClientTimeout(total=5)
            result = await _check_v1_instance(session, domain, timeout)
            assert result["open_signup"] is False
            assert result["registration_mode"] == "approval"

@pytest.mark.asyncio
async def test_check_server_fallback():
    domain = "fallback.social"

    mock_resp_v2 = MagicMock(spec=aiohttp.ClientResponse)
    mock_resp_v2.status = 404

    mock_resp_v1 = MagicMock(spec=aiohttp.ClientResponse)
    mock_resp_v1.status = 200
    mock_resp_v1.headers = {}
    async def mock_read_v1():
        return b'{"registrations": true, "approval_required": false}'
    mock_resp_v1.read = mock_read_v1

    with patch("aiohttp.ClientSession.get") as mock_get:
        m1 = MagicMock()
        m1.__aenter__.return_value = mock_resp_v2
        m2 = MagicMock()
        m2.__aenter__.return_value = mock_resp_v1

        mock_get.side_effect = [m1, m2]

        async with aiohttp.ClientSession() as session:
            result = await check_server(session, domain, 5)
            assert result["open_signup"] is True
            assert result["registration_mode"] == "open"
            assert result["error"] is None

@pytest.mark.asyncio
async def test_check_server_all_fail():
    domain = "fail.social"

    mock_resp_v2 = MagicMock(spec=aiohttp.ClientResponse)
    mock_resp_v2.status = 500

    mock_resp_v1 = MagicMock(spec=aiohttp.ClientResponse)
    mock_resp_v1.status = 500

    with patch("aiohttp.ClientSession.get") as mock_get:
        m1 = MagicMock()
        m1.__aenter__.return_value = mock_resp_v2
        m2 = MagicMock()
        m2.__aenter__.return_value = mock_resp_v1

        mock_get.side_effect = [m1, m2]

        async with aiohttp.ClientSession() as session:
            result = await check_server(session, domain, 5)
            assert result["open_signup"] is None
            assert "HTTP 500" in result["error"]
