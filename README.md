# truenas-backup
This repository contains a single script, `truenas-backup.py` (alias `truenas.py`), for fetching a TrueNAS configuration backup via the TrueNAS websocket API (DDP protocol) and storing it locally.

## What it does

- Connects to a TrueNAS host via Secure WebSocket (`wss://<TRUENAS_HOST>/websocket`).
- Authenticates with `auth.login_with_api_key` using an API key loaded from `.truenas-api-key` in the script directory.
- Calls `core.download` with `config.save` to request a backup tar download URL.
- Downloads the backup file to `OUTPUT_FILE` (default includes timestamp)
- Validates the file size (must be >= 50 KB).
- Logs all events in JSONL format to `TRUENAS_LOG_FILE`.

## Configuration

Edit the constants at the top of `truenas.py`:

- `TRUENAS_HOST` – TrueNAS host/fqdn
- `API_KEY` – not normally set; script reads from `.truenas-api-key`
- `OUTPUT_FILE` – file path where the downloaded backup is saved
- `VERIFY_SSL` – set `True` for proper TLS verification, `False` to bypass cert checks
- `LOG_FILE` – path to JSONL audit/metrics file

Create `.truenas-api-key` next to `truenas.py` containing your API key lone on one line.

## Usage

```bash
python3 truenas.py
```

When successful, output contains:

- `URL` returned from TrueNAS for config download
- `Backup complete: <OUTPUT_FILE>`

## Dependencies

- Python 3.8+
- `requests`
- `websockets`
- `python-dotenv`
- `urllib3` (used by `requests`)

Install with:

```bash
pip install -r requirements.txt
```

## Environment variables and .env support
The script now reads config from a `.env` file (via `python-dotenv`), for example:

```env
TRUENAS_HOST=nas.yourdomain.com
API_KEY=xxxxxxxxxxxxxxxxxxxxxxxxxxxx
OUTPUT_FILE_ROOT=/truenas/
VERIFY_SSL=false
TRUENAS_LOG_FILE=/truenas/logs/truenas.jsonl
```

- If `OUTPUT_FILE` is set in `.env`, it is used directly.
- Otherwise `OUTPUT_FILE` is built from `OUTPUT_FILE_ROOT` + timestamp.
- `VERIFY_SSL=false` disables TLS verification and suppresses `InsecureRequestWarning`.

## Behavior

- Logs events using `log_event(level, event, details, extra)`.
- Exits non-zero on error (API/auth failures, download issues, validation failures).

## Notes
- The script is designed for local automation and the downloaded file should be secured carefully because it stores snesitive TrueNAS informaton.
- Validate `TRUENAS_HOST` and SSL settings before exposing this script to untrusted networks.