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
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import aiohttp
from mastodon import Mastodon

# ---------------------------------------------------------------------------
# Configuration defaults
# ---------------------------------------------------------------------------
DEFAULT_CONCURRENCY = 20
DEFAULT_TIMEOUT = 15  # seconds per request
DEFAULT_STATUS_FILE = "server_status.json"
DEFAULT_OUTPUT_CSV = "open_signups.csv"
DEFAULT_RECHECK_HOURS = 24  # skip servers checked within this window

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
    client = Mastodon(
        access_token=access_token,
        api_base_url=api_base_url,
    )
    # /api/v1/instance/peers – returns a plain list of domain strings
    peers: list[str] = client.instance_peers()
    log.info("Fetched %d known peers from %s", len(peers), api_base_url)
    return peers


# ---------------------------------------------------------------------------
# Step 2 – Check a single server for open signups
# ---------------------------------------------------------------------------
async def check_server(
    session: aiohttp.ClientSession,
    domain: str,
    timeout: float,
) -> dict:
    """
    Query a remote server's /api/v2/instance (falling back to /api/v1/instance)
    and determine whether signups are open without moderator approval.

    Returns a dict with:
      - domain
      - open_signup (bool | None if unreachable)
      - registration_mode (str | None)
      - error (str | None)
      - checked_at (ISO-8601 timestamp)
    """
    result = {
        "domain": domain,
        "open_signup": None,
        "registration_mode": None,
        "error": None,
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }
    req_timeout = aiohttp.ClientTimeout(total=timeout)

    # --- Try /api/v2/instance first (Mastodon 4.x) -------------------------
    try:
        url_v2 = f"https://{domain}/api/v2/instance"
        async with session.get(url_v2, timeout=req_timeout) as resp:
            if resp.status == 200:
                data = await resp.json(content_type=None)
                # v2 returns registrations.approval_required (bool) and
                # registrations.enabled (bool)
                regs = data.get("registrations", {})
                enabled = regs.get("enabled", False)
                approval = regs.get("approval_required", True)

                if enabled and not approval:
                    result["open_signup"] = True
                    result["registration_mode"] = "open"
                elif enabled and approval:
                    result["open_signup"] = False
                    result["registration_mode"] = "approval"
                else:
                    result["open_signup"] = False
                    result["registration_mode"] = "closed"
                return result
    except Exception:
        pass  # fall through to v1

    # --- Fallback to /api/v1/instance (Mastodon 3.x and others) -------------
    try:
        url_v1 = f"https://{domain}/api/v1/instance"
        async with session.get(url_v1, timeout=req_timeout) as resp:
            if resp.status == 200:
                data = await resp.json(content_type=None)
                # v1 returns registrations (bool) and approval_required (bool)
                registrations = data.get("registrations", False)
                approval = data.get("approval_required", True)

                if registrations and not approval:
                    result["open_signup"] = True
                    result["registration_mode"] = "open"
                elif registrations and approval:
                    result["open_signup"] = False
                    result["registration_mode"] = "approval"
                else:
                    result["open_signup"] = False
                    result["registration_mode"] = "closed"
                return result
            else:
                result["error"] = f"HTTP {resp.status}"
    except asyncio.TimeoutError:
        result["error"] = "timeout"
    except Exception as exc:
        result["error"] = str(exc)[:120]

    return result


# ---------------------------------------------------------------------------
# Step 3 – Scan all peers concurrently
# ---------------------------------------------------------------------------
async def scan_all(
    domains: list[str],
    concurrency: int,
    timeout: float,
) -> list[dict]:
    """Check every domain with bounded concurrency."""
    semaphore = asyncio.Semaphore(concurrency)
    results: list[dict] = []

    async def _limited_check(session: aiohttp.ClientSession, domain: str):
        async with semaphore:
            return await check_server(session, domain, timeout)

    connector = aiohttp.TCPConnector(limit=concurrency, enable_cleanup_closed=True)
    async with aiohttp.ClientSession(connector=connector) as session:
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
def load_status(path: str) -> dict:
    """Load the persistent server status file."""
    if os.path.exists(path):
        with open(path, "r") as fh:
            return json.load(fh)
    return {}


def save_status(path: str, status: dict) -> None:
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
        required=True,
        help="Base URL of your home Mastodon instance (e.g. https://mastodon.social)",
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


def main() -> None:
    args = parse_args()

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
                last = datetime.fromisoformat(prev["checked_at"])
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
        start = time.monotonic()
        results = asyncio.run(
            scan_all(to_check, args.concurrency, args.timeout)
        )
        elapsed = time.monotonic() - start
        log.info("Scan finished in %.1f s", elapsed)

        # Merge results into the persistent status
        for r in results:
            status[r["domain"]] = r
    else:
        log.info("Nothing to check – all peers within recheck window.")

    # 4. Save full status
    save_status(args.status_file, status)

    # 5. Produce blocklist CSV from all currently-known open-signup servers
    open_domains = [
        domain for domain, info in status.items()
        if info.get("open_signup") is True
    ]
    write_blocklist_csv(args.output, open_domains)

    # Summary
    total = len(status)
    open_count = len(open_domains)
    err_count = sum(1 for v in status.values() if v.get("error"))
    log.info(
        "Summary: %d servers tracked, %d open signups, %d unreachable/errors",
        total,
        open_count,
        err_count,
    )


if __name__ == "__main__":
    main()
