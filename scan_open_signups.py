#!/usr/bin/env python3
"""
Scan known fediverse servers for open signups (no moderator approval required).

Connects to a home Mastodon-compatible server via admin API to get the list of
known peers, then checks each peer's public instance API to determine whether
signups are open without moderator approval.

Outputs:
  - open_signups.csv   : Mastodon-compatible blocklist CSV of open-signup servers
  - server_status.json : All servers with last-checked timestamps for incremental runs
"""

import argparse
import asyncio
import csv
import json
import logging
import os
import re
import signal
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import aiohttp
from dotenv import load_dotenv
from mastodon import Mastodon, MastodonError

# ---------------------------------------------------------------------------
# Configuration defaults
# ---------------------------------------------------------------------------
DEFAULT_CONCURRENCY = 20
DEFAULT_TIMEOUT = 15  # seconds per request
DEFAULT_STATUS_FILE = "server_status.json"
DEFAULT_OUTPUT_CSV = "open_signups.csv"
DEFAULT_RECHECK_HOURS = 24  # skip servers checked within this window
MAX_RESPONSE_BYTES = 1_000_000  # 1 MB – ignore absurdly large responses
USER_AGENT = "FediverseSignupScanner/1.0"
DOMAIN_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)+$")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Step 1 – Fetch known peers from the home server
# ---------------------------------------------------------------------------
def fetch_known_peers(api_base_url: str, access_token: str) -> list[str]:
    """Use Mastodon.py to retrieve the peer list from the home instance."""
    try:
        client = Mastodon(
            access_token=access_token,
            api_base_url=api_base_url,
            request_timeout=30,
        )
        # /api/v1/instance/peers – returns a plain list of domain strings
        peers: list[str] = client.instance_peers()
    except MastodonError as exc:
        log.error("Mastodon API error fetching peers from %s: %s", api_base_url, exc)
        return []
    except Exception as exc:
        log.error("Unexpected error fetching peers from %s: %s", api_base_url, exc)
        return []

    if not isinstance(peers, list):
        log.error("Unexpected response type from instance_peers: %s", type(peers))
        return []

    # Validate and sanitise domain strings
    clean: list[str] = []
    for p in peers:
        if not isinstance(p, str):
            continue
        p = p.strip().lower()
        if p and DOMAIN_RE.match(p):
            clean.append(p)
    skipped = len(peers) - len(clean)
    if skipped:
        log.warning("Skipped %d invalid domain entries from peer list", skipped)
    log.info("Fetched %d valid peers from %s", len(clean), api_base_url)
    return clean


# ---------------------------------------------------------------------------
# Step 2 – Check a single server for open signups
# ---------------------------------------------------------------------------
async def _safe_read_json(resp: aiohttp.ClientResponse) -> Optional[Dict[str, Any]]:
    """Read a JSON response body with a size guard to prevent memory abuse."""
    content_length = resp.headers.get("Content-Length")
    if content_length and int(content_length) > MAX_RESPONSE_BYTES:
        return None
    body = await resp.read()
    if len(body) > MAX_RESPONSE_BYTES:
        return None
    try:
        return json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None


async def _check_v2_instance(
    session: aiohttp.ClientSession,
    domain: str,
    timeout: aiohttp.ClientTimeout,
) -> Optional[Dict[str, Any]]:
    """
    Try /api/v2/instance (Mastodon 4.0+).
    Returns (open_signup, registration_mode) if successful, else None.
    """
    try:
        url_v2 = f"https://{domain}/api/v2/instance"
        async with session.get(url_v2, timeout=timeout, allow_redirects=False) as resp:
            if resp.status == 200:
                data = await _safe_read_json(resp)
                if data:
                    regs = data.get("registrations", {})
                    if not isinstance(regs, dict):
                        regs = {}
                    enabled = bool(regs.get("enabled", False))
                    approval_required = bool(regs.get("approval_required", True))

                    if enabled and not approval_required:
                        return {"open_signup": True, "registration_mode": "open"}
                    elif enabled and approval_required:
                        return {"open_signup": False, "registration_mode": "approval"}
                    else:
                        return {"open_signup": False, "registration_mode": "closed"}
                return {"error": "invalid/oversized JSON"}
            return {"error": f"HTTP {resp.status}"}
    except asyncio.TimeoutError:
        return {"error": "timeout"}
    except (aiohttp.ClientError, Exception) as exc:
        return {"error": str(exc)[:120]}


async def _check_v1_instance(
    session: aiohttp.ClientSession,
    domain: str,
    timeout: aiohttp.ClientTimeout,
) -> Optional[Dict[str, Any]]:
    """
    Try /api/v1/instance (Mastodon 2.7–3.x).
    Returns (open_signup, registration_mode) if successful, else None.
    """
    try:
        url_v1 = f"https://{domain}/api/v1/instance"
        async with session.get(url_v1, timeout=timeout, allow_redirects=False) as resp:
            if resp.status == 200:
                data = await _safe_read_json(resp)
                if data:
                    registrations_raw = data.get("registrations", False)
                    if isinstance(registrations_raw, dict):
                        enabled = bool(registrations_raw.get("enabled", False))
                        approval_required = bool(registrations_raw.get("approval_required", True))
                    else:
                        enabled = bool(registrations_raw)
                        approval_required = bool(data.get("approval_required", True))

                    if enabled and not approval_required:
                        return {"open_signup": True, "registration_mode": "open"}
                    elif enabled and approval_required:
                        return {"open_signup": False, "registration_mode": "approval"}
                    else:
                        return {"open_signup": False, "registration_mode": "closed"}
                return {"error": "invalid/oversized JSON"}
            return {"error": f"HTTP {resp.status}"}
    except asyncio.TimeoutError:
        return {"error": "timeout"}
    except (aiohttp.ClientError, Exception) as exc:
        return {"error": str(exc)[:120]}


async def check_server(
    session: aiohttp.ClientSession,
    domain: str,
    timeout: float,
) -> Dict[str, Any]:
    """
    Query a remote server's API to determine whether signups are open.
    Falls back from V2 to V1.
    """
    result = {
        "domain": domain,
        "open_signup": None,
        "registration_mode": None,
        "error": None,
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }
    req_timeout = aiohttp.ClientTimeout(
        total=timeout,
        connect=min(timeout, 10),
        sock_connect=min(timeout, 10),
        sock_read=timeout,
    )

    # 1. Try V2
    v2_res = await _check_v2_instance(session, domain, req_timeout)
    if v2_res and "error" not in v2_res:
        result.update(v2_res)
        return result

    # 2. Try V1 fallback
    v1_res = await _check_v1_instance(session, domain, req_timeout)
    if v1_res and "error" not in v1_res:
        result.update(v1_res)
        return result

    # 3. Handle failure
    v2_err = v2_res.get("error") if v2_res else "unknown"
    v1_err = v1_res.get("error") if v1_res else "unknown"
    result["error"] = f"v1: {v1_err} (v2: {v2_err})"
    return result


# ---------------------------------------------------------------------------
# Step 3 – Scan all peers concurrently
# ---------------------------------------------------------------------------
async def scan_all(
    domains: List[str],
    concurrency: int,
    timeout: float,
) -> List[Dict[str, Any]]:
    """Check every domain with bounded concurrency and a global safety timeout."""
    semaphore = asyncio.Semaphore(concurrency)
    results: list[dict] = []

    async def _limited_check(session: aiohttp.ClientSession, domain: str) -> dict:
        async with semaphore:
            try:
                # Per-task hard deadline: 2x the request timeout to account
                # for v2 → v1 fallback, plus a small margin.
                return await asyncio.wait_for(
                    check_server(session, domain, timeout),
                    timeout=timeout * 2 + 5,
                )
            except asyncio.TimeoutError:
                return {
                    "domain": domain,
                    "open_signup": None,
                    "registration_mode": None,
                    "error": "task timeout (stuck)",
                    "checked_at": datetime.now(timezone.utc).isoformat(),
                }
            except Exception as exc:
                return {
                    "domain": domain,
                    "open_signup": None,
                    "registration_mode": None,
                    "error": f"unexpected: {str(exc)[:100]}",
                    "checked_at": datetime.now(timezone.utc).isoformat(),
                }

    connector = aiohttp.TCPConnector(
        limit=concurrency,
        enable_cleanup_closed=True,
        ttl_dns_cache=300,
        force_close=True,
    )
    headers = {"User-Agent": USER_AGENT}
    async with aiohttp.ClientSession(connector=connector, headers=headers) as session:
        tasks = [_limited_check(session, d) for d in domains]
        total = len(tasks)
        done = 0
        for coro in asyncio.as_completed(tasks):
            res = await coro
            results.append(res)
            done += 1
            if done % 100 == 0 or done == total:
                log.info("Progress: %d / %d checked", done, total)

    return results


# ---------------------------------------------------------------------------
# Step 4 – Persist status and produce outputs
# ---------------------------------------------------------------------------
def load_status(path: str) -> Dict[str, Any]:
    """Load the persistent server status file, tolerating corruption."""
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r") as fh:
            data = json.load(fh)
        if not isinstance(data, dict):
            log.warning("Status file is not a JSON object – starting fresh")
            return {}
        return data
    except (json.JSONDecodeError, OSError) as exc:
        log.warning("Could not load status file %s: %s – starting fresh", path, exc)
        # Keep the corrupt file around for manual inspection
        backup = path + ".corrupt"
        try:
            os.replace(path, backup)
            log.info("Moved corrupt status file to %s", backup)
        except OSError:
            pass
        return {}


def save_status(path: str, status: Dict[str, Any]) -> None:
    """Write the server status file atomically."""
    tmp = path + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(status, fh, indent=2)
    os.replace(tmp, path)
    log.info("Saved status for %d servers to %s", len(status), path)


def write_blocklist_csv(path: str, domains: list[str]) -> None:
    """
    Write a Mastodon-compatible domain blocklist CSV.

    Mastodon import format columns:
      #domain, #severity, #reject_media, #reject_reports, #public_comment,
      #obfuscate
    """
    with open(path, "w", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow([
            "#domain",
            "#severity",
            "#reject_media",
            "#reject_reports",
            "#public_comment",
            "#obfuscate",
        ])
        for domain in sorted(domains):
            writer.writerow([
                domain,
                "suspend",
                "true",
                "true",
                "Open registration – no moderator approval required",
                "false",
            ])
    log.info("Wrote %d open-signup servers to %s", len(domains), path)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Scan fediverse peers for open signups and produce a blocklist CSV.",
    )
    p.add_argument(
        "--server",
        default=os.environ.get("MASTODON_SERVER"),
        help="Base URL of your home Mastodon instance (e.g. https://mastodon.social) [default: $MASTODON_SERVER]",
    )
    p.add_argument(
        "--token",
        default=os.environ.get("MASTODON_ACCESS_TOKEN", ""),
        help="Admin API access token (or set MASTODON_ACCESS_TOKEN env var)",
    )
    p.add_argument(
        "--concurrency",
        type=int,
        default=DEFAULT_CONCURRENCY,
        help=f"Max concurrent checks (default: {DEFAULT_CONCURRENCY})",
    )
    p.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help=f"Per-request timeout in seconds (default: {DEFAULT_TIMEOUT})",
    )
    p.add_argument(
        "--status-file",
        default=DEFAULT_STATUS_FILE,
        help=f"Path to server status JSON (default: {DEFAULT_STATUS_FILE})",
    )
    p.add_argument(
        "--output",
        default=DEFAULT_OUTPUT_CSV,
        help=f"Output CSV path (default: {DEFAULT_OUTPUT_CSV})",
    )
    p.add_argument(
        "--recheck-hours",
        type=float,
        default=DEFAULT_RECHECK_HOURS,
        help=f"Skip servers checked within N hours (default: {DEFAULT_RECHECK_HOURS})",
    )
    p.add_argument(
        "--force",
        action="store_true",
        help="Ignore recheck window and scan every peer",
    )
    return p.parse_args()


def _save_and_report(status: Dict[str, Any], args: argparse.Namespace) -> None:
    """Save status + CSV and print summary.  Called on normal exit and on interrupt."""
    save_status(args.status_file, status)

    open_domains = [
        domain for domain, info in status.items()
        if info.get("open_signup") is True
    ]
    write_blocklist_csv(args.output, open_domains)

    total = len(status)
    open_count = len(open_domains)
    err_count = sum(1 for v in status.values() if v.get("error"))
    log.info(
        "Summary: %d servers tracked, %d open signups, %d unreachable/errors",
        total,
        open_count,
        err_count,
    )


def main() -> None:
    load_dotenv()
    args = parse_args()

    if not args.server:
        log.error("No server URL provided. Use --server or set MASTODON_SERVER.")
        sys.exit(1)

    if not args.token:
        log.error("No access token provided. Use --token or set MASTODON_ACCESS_TOKEN.")
        sys.exit(1)

    # 1. Fetch peers from the home server
    peers = fetch_known_peers(args.server, args.token)
    if not peers:
        log.error("No peers returned – check your server URL and token.")
        sys.exit(1)

    # 2. Load previous status and decide which peers to re-check
    status = load_status(args.status_file)
    now = datetime.now(timezone.utc)

    if args.force:
        to_check = peers
    else:
        to_check = []
        for domain in peers:
            prev = status.get(domain)
            if prev and "checked_at" in prev:
                try:
                    last = datetime.fromisoformat(prev["checked_at"])
                except (ValueError, TypeError):
                    # Malformed timestamp – recheck this domain
                    to_check.append(domain)
                    continue
                age_hours = (now - last).total_seconds() / 3600
                if age_hours < args.recheck_hours:
                    continue
            to_check.append(domain)

    log.info(
        "%d peers total, %d to (re)check (recheck window: %.1f h)",
        len(peers),
        len(to_check),
        args.recheck_hours,
    )

    # 3. Run the async scan
    if to_check:
        # Register signal handler so Ctrl+C saves partial progress
        interrupted = False

        def _on_sigint(sig, frame):
            nonlocal interrupted
            if interrupted:
                # Second Ctrl+C – hard exit
                log.warning("Forced exit – saving what we have")
                _save_and_report(status, args)
                sys.exit(1)
            interrupted = True
            log.warning("Interrupt received – finishing current batch then saving…")

        prev_handler = signal.signal(signal.SIGINT, _on_sigint)

        start = time.monotonic()
        try:
            results = asyncio.run(
                scan_all(to_check, args.concurrency, args.timeout)
            )
        except KeyboardInterrupt:
            log.warning("Scan interrupted by user")
            results = []
        finally:
            signal.signal(signal.SIGINT, prev_handler)

        elapsed = time.monotonic() - start
        log.info("Scan finished in %.1f s (%d results)", elapsed, len(results))

        # Merge results into the persistent status
        for r in results:
            status[r["domain"]] = r
    else:
        log.info("Nothing to check – all peers within recheck window.")

    # 4. Save status + CSV and report
    _save_and_report(status, args)


if __name__ == "__main__":
    main()
