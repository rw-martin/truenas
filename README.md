# truenas-backup

`truenas-backup.py` fetches a TrueNAS configuration backup through the TrueNAS WebSocket API and saves it locally as a `.tar` file.

## What It Does

- Connects to `wss://<host>/websocket`
- Authenticates with `auth.login_with_api_key`
- Calls `core.download` for `config.save`
- Downloads the returned backup archive
- Validates that the downloaded file is at least 50 KB
- Writes a single JSONL audit entry for each run

## Requirements

- Python 3.10+
- A TrueNAS API key

Install dependencies with:

```bash
python3 -m pip install -r requirements.txt
```

## Configuration

Configuration can come from CLI flags, environment variables, or a `.truenas-api-key` file.

Precedence is:

1. CLI arguments
2. Environment variables or `.env`
3. `.truenas-api-key` for the API key only
4. Built-in defaults

Supported environment variables:

- `TRUENAS_HOST`
- `API_KEY`
- `OUTPUT_FILE`
- `OUTPUT_FILE_ROOT`
- `TRUENAS_LOG_FILE`
- `VERIFY_SSL`

Example `.env`:

```env
TRUENAS_HOST=nas.example.com
API_KEY=your-api-key
OUTPUT_FILE_ROOT=/var/backups/truenas
TRUENAS_LOG_FILE=/var/log/truenas/truenas.jsonl
VERIFY_SSL=true
```

If `API_KEY` is not set, the script also checks for `.truenas-api-key` in the same directory as the script.

## CLI Usage

Basic usage:

```bash
python3 truenas-backup.py
```

Available switches:

- `--host`
- `--api-key`
- `--output-file`
- `--output-root`
- `--log-file`
- `--verify-ssl`
- `--insecure`

Examples:

```bash
python3 truenas-backup.py --host truenas.local --insecure
```

```bash
python3 truenas-backup.py \
  --host nas.example.com \
  --output-root /var/backups/truenas \
  --log-file /var/log/truenas/truenas.jsonl \
  --verify-ssl
```

`--output-file` writes to an exact path.

`--output-root` creates a timestamped file like `truenas-config-YYYYMMDD-HHMMSS.tar`.

`--verify-ssl` and `--insecure` are mutually exclusive. If neither is passed, the script uses `VERIFY_SSL` from the environment and defaults to insecure mode if unset.

## Logging

Each run appends one JSON object to the configured JSONL log file, including:

- timestamp
- pid
- host
- status
- duration
- backup file path
- job ID when available
- file size when available
- error text on failure

## Notes

- The backup can contain sensitive TrueNAS configuration data. Store it securely.
- If TLS verification is disabled, certificate warnings are suppressed for cleaner automation output.
- `python-dotenv` is optional at runtime, but included in `requirements.txt` so `.env` loading works out of the box.
