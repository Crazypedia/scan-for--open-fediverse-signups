# scan-for--open-fediverse-signups

Scans known fediverse servers for open sign-ups (no moderator approval required) and generates a Mastodon-compatible blocklist CSV.

## How it works

```
┌──────────────────────────┐
│  Your Mastodon Instance  │
│  (admin API + token)     │
└────────────┬─────────────┘
             │ 1. GET /api/v1/instance/peers
             ▼
     List of ~N,000 peer domains
             │
             │ 2. For each peer (20 concurrent, 15s timeout):
             │    GET https://{peer}/api/v2/instance
             │    fallback → /api/v1/instance
             ▼
   ┌─────────────────────┐
   │  registrations:     │
   │    enabled: true     │  ──► open_signup = true
   │    approval: false   │
   └─────────────────────┘
             │
             ▼
   ┌─────────────────────────────────────┐
   │  open_signups.csv   (blocklist)     │
   │  server_status.json (all servers)   │
   └─────────────────────────────────────┘
```

### Step-by-step

1. **Fetch peers** – Uses `Mastodon.py` with your admin access token to call `/api/v1/instance/peers` and get every domain your server knows about.
2. **Check each peer** – Concurrently hits each peer's public `/api/v2/instance` endpoint (falling back to `/api/v1/instance`). Looks at `registrations.enabled` and `registrations.approval_required`.
3. **Persist state** – Writes `server_status.json` with every server's last-checked timestamp, registration mode, and any errors. On subsequent runs, servers checked within the recheck window (default 24 h) are skipped.
4. **Output blocklist** – Servers where signups are open **without** moderator approval are written to `open_signups.csv` in Mastodon's domain-block import format.

## Setup

```bash
pip install -r requirements.txt
```

Copy `.env.example` to `.env` and fill in your values:

```bash
cp .env.example .env
# Edit .env with your instance URL and access token
```

### Getting an access token

1. On your Mastodon instance go to **Preferences → Development → New Application**
2. Set the required scopes: `admin:read`
3. Save and copy the **access token**

## Usage

```bash
# Basic run
python3 scan_open_signups.py \
  --server https://your-instance.example.com \
  --token YOUR_ACCESS_TOKEN

# Or with environment variable
export MASTODON_ACCESS_TOKEN=YOUR_ACCESS_TOKEN
python3 scan_open_signups.py --server https://your-instance.example.com

# Customize concurrency and timeout
python3 scan_open_signups.py \
  --server https://your-instance.example.com \
  --concurrency 30 \
  --timeout 10

# Force recheck of all servers (ignore 24h window)
python3 scan_open_signups.py \
  --server https://your-instance.example.com \
  --force
```

### CLI options

| Flag | Default | Description |
|------|---------|-------------|
| `--server` | *(required)* | Your Mastodon instance URL |
| `--token` | `$MASTODON_ACCESS_TOKEN` | Admin access token |
| `--concurrency` | `20` | Max simultaneous peer checks |
| `--timeout` | `15` | Per-request timeout in seconds |
| `--status-file` | `server_status.json` | Path to persistent status file |
| `--output` | `open_signups.csv` | Output blocklist CSV path |
| `--recheck-hours` | `24` | Skip recently-checked servers |
| `--force` | `false` | Recheck everything |

## Output files

### `open_signups.csv`

Mastodon-compatible domain block CSV:

```csv
#domain,#severity,#reject_media,#reject_reports,#public_comment,#obfuscate
example.social,suspend,true,true,Open registration – no moderator approval required,false
```

Import via **Administration → Moderation → Federation → Import**.

### `server_status.json`

JSON dictionary keyed by domain with fields:

```json
{
  "example.social": {
    "domain": "example.social",
    "open_signup": true,
    "registration_mode": "open",
    "error": null,
    "checked_at": "2026-03-03T12:00:00+00:00"
  }
}
```
