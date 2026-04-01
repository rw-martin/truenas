# truenas-backup

`truenas-backup.py` fetches a TrueNAS configuration backup through the TrueNAS WebSocket API, saves it locally as a `.tar` file, and can optionally use HashiCorp Vault Transit for envelope encryption.

## What It Does

- Connects to `wss://<host>/websocket`
- Authenticates with `auth.login_with_api_key`
- Calls `core.download` for `config.save`
- Downloads the returned backup archive
- Validates that the downloaded file is at least 50 KB
- Optionally keeps the downloaded backup only in memory, asks Vault Transit for a data key, and encrypts the backup locally into an envelope file
- Writes JSONL log entries for each major stage plus a final run summary

## Requirements

- Python 3.10+
- A TrueNAS API key
- A Vault token if using encryption or decryption

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
- `VAULT_TRANSIT_ENABLED`
- `VAULT_ADDR`
- `VAULT_TOKEN`
- `VAULT_TRANSIT_KEY`
- `VAULT_TRANSIT_MOUNT`
- `VAULT_NAMESPACE`
- `VAULT_VERIFY_SSL`
- `VAULT_TRANSIT_OUTPUT_FILE`
- `VAULT_TRANSIT_DELETE_PLAINTEXT`

Example `.env`:

```env
TRUENAS_HOST=nas.example.com
API_KEY=your-api-key
OUTPUT_FILE_ROOT=/var/backups/truenas
TRUENAS_LOG_FILE=/var/log/truenas/truenas.jsonl
VERIFY_SSL=true
VAULT_TRANSIT_ENABLED=false
```

If `API_KEY` is not set, the script also checks for `.truenas-api-key` in the same directory as the script.

Vault Transit configuration:

- `VAULT_TRANSIT_ENABLED=true` turns encryption on
- `VAULT_ADDR` is the base Vault URL, for example `https://vault.example.com`
- `VAULT_TOKEN` is the Vault token used for the Transit request
- `VAULT_TRANSIT_KEY` is the Transit key name
- `VAULT_TRANSIT_MOUNT` defaults to `transit`
- `VAULT_NAMESPACE` is optional and useful in Vault Enterprise or HCP
- `VAULT_VERIFY_SSL` defaults to `VERIFY_SSL`
- `VAULT_TRANSIT_OUTPUT_FILE` defaults to `<backup file>.vault.json`
- `VAULT_TRANSIT_DELETE_PLAINTEXT` defaults to `true`; when Vault encryption is enabled, the plaintext tar is not written to disk unless you set this to `false`

Example Vault-enabled `.env`:

```env
TRUENAS_HOST=nas.example.com
API_KEY=your-truenas-api-key
OUTPUT_FILE_ROOT=/var/backups/truenas
TRUENAS_LOG_FILE=/var/log/truenas/truenas.jsonl
VERIFY_SSL=true
VAULT_TRANSIT_ENABLED=true
VAULT_ADDR=https://vault.example.com
VAULT_TOKEN=your-vault-token
VAULT_TRANSIT_KEY=truenas-backup
VAULT_TRANSIT_MOUNT=transit
VAULT_NAMESPACE=admin
VAULT_VERIFY_SSL=true
VAULT_TRANSIT_DELETE_PLAINTEXT=true
```

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

Vault Transit is configured through environment variables today rather than dedicated CLI switches.

When Vault Transit is enabled, the script keeps the downloaded backup in memory, requests a wrapped data key from Transit, encrypts the backup locally with AES-256-GCM, and writes a JSON envelope file. By default, the plaintext tar is never written to disk in this mode; set `VAULT_TRANSIT_DELETE_PLAINTEXT=false` to also retain the unencrypted tar after encryption succeeds. The Vault key version is stored inside the envelope metadata.

## Decryption

Use `truenas-decrypt.py` to restore a `.vault.json` envelope back into a tar file:

```bash
python3 truenas-decrypt.py /path/to/truenas-config-20260401-203849.tar.vault.json
```

It uses `VAULT_ADDR`, `VAULT_TOKEN`, `VAULT_TRANSIT_MOUNT`, `VAULT_NAMESPACE`, and `VAULT_VERIFY_SSL` from `.env` by default. You can override those with CLI flags and write to a different location with `--output-file`.

Decryption also writes JSONL log entries to the same `TRUENAS_LOG_FILE`.

## Logging

The script writes stage-level JSONL events for:

- `config_backup_started`
- `config_backup_download_started`
- `config_backup_download_completed`
- `vault_transit_encrypt_started`
- `vault_transit_encrypt_completed`
- `vault_transit_encrypt_failed`
- `config_restore_started`
- `vault_transit_decrypt_started`
- `vault_transit_decrypt_completed`
- `config_restore_failed`
- `config_backup_failed`
- `config_backup`
- `config_restore`

The final `config_backup` event includes:

- timestamp
- pid
- host
- status
- duration
- backup file path
- TrueNAS job ID when available, stored as `truenas_job_id`
- backup file size when available, stored as `backup_filesize_bytes`
- Vault enablement and encryption status
- envelope output path and size when available
- error text on failure

The final `config_restore` event includes:

- timestamp
- pid
- host
- status
- duration
- envelope file path
- restored output file path when available
- restored size in bytes when available
- Vault Transit key name and key version when available
- error text on failure

## Notes

- The backup can contain sensitive TrueNAS configuration data. Store it securely.
- Vault Transit is used for envelope encryption here, not for direct whole-file `encrypt` operations.
- The encrypted output is stored as a JSON envelope containing the wrapped data key, AES-GCM nonce, and encrypted backup payload rather than as another tar archive.
- With Vault encryption enabled, the backup tar lives in memory during processing and is only written to disk if plaintext retention is explicitly enabled.
- `requirements.txt` covers both backup and decrypt workflows, including `cryptography` for AES-GCM envelope handling.
- If TLS verification is disabled, certificate warnings are suppressed for cleaner automation output.
- `python-dotenv` is optional at runtime, but included in `requirements.txt` so `.env` loading works out of the box.
