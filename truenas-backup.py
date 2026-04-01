#!/usr/bin/env python3

import argparse
import asyncio
import base64
import json
import os
import socket
import ssl
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

try:
    from dotenv import load_dotenv
except ImportError:
    def load_dotenv() -> None:
        return None

if TYPE_CHECKING:
    import websockets

load_dotenv()

TRUE_VALUES = {"1", "true", "yes", "on"}
REQUEST_TIMEOUT = (10, 60)
WEBSOCKET_OPEN_TIMEOUT = 10
WEBSOCKET_MESSAGE_TIMEOUT = 30
MIN_BACKUP_SIZE_BYTES = 50_000
BASE_DIR = Path(sys.path[0])
OS_PID = os.getpid()
HOST_NAME = socket.gethostname().split(".")[0]


def parse_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in TRUE_VALUES


@dataclass(frozen=True)
class VaultTransitSettings:
    address: str
    token: str
    key_name: str
    mount_path: str
    verify_ssl: bool
    namespace: str | None
    ciphertext_file: Path
    delete_plaintext: bool


@dataclass(frozen=True)
class Settings:
    truenas_host: str
    api_key: str
    verify_ssl: bool
    log_file: Path
    output_file: Path
    vault_transit: VaultTransitSettings | None

    @classmethod
    def load(cls, args: argparse.Namespace) -> "Settings":
        verify_ssl = resolve_verify_ssl(args)
        api_key = args.api_key or os.getenv("API_KEY") or load_api_key_from_file()
        if not api_key:
            raise SystemExit("API key missing; set API_KEY in .env or .truenas-api-key")

        log_file = Path(args.log_file or os.getenv("TRUENAS_LOG_FILE", BASE_DIR / "truenas.jsonl"))
        output_file = resolve_output_file(args)

        return cls(
            truenas_host=args.host or os.getenv("TRUENAS_HOST", "truenas.local"),
            api_key=api_key,
            verify_ssl=verify_ssl,
            log_file=log_file,
            output_file=output_file,
            vault_transit=load_vault_transit_settings(verify_ssl, output_file),
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Back up TrueNAS configuration via WebSocket API.")
    parser.add_argument("--host", help="TrueNAS hostname or IP address")
    parser.add_argument("--api-key", help="TrueNAS API key")
    parser.add_argument("--output-file", help="Exact path for the backup tar file")
    parser.add_argument("--output-root", help="Directory for timestamped backup output")
    parser.add_argument("--log-file", help="Path for JSONL log output")
    parser.add_argument(
        "--verify-ssl",
        action="store_true",
        help="Enable TLS certificate verification",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Disable TLS certificate verification",
    )
    return parser


def resolve_verify_ssl(args: argparse.Namespace) -> bool:
    if args.verify_ssl and args.insecure:
        raise SystemExit("Choose either --verify-ssl or --insecure, not both")
    if args.verify_ssl:
        return True
    if args.insecure:
        return False
    return parse_bool(os.getenv("VERIFY_SSL"), default=False)


def resolve_output_file(args: argparse.Namespace) -> Path:
    explicit_output = args.output_file or os.getenv("OUTPUT_FILE")
    if explicit_output:
        return Path(explicit_output)

    output_root = Path(args.output_root or os.getenv("OUTPUT_FILE_ROOT", "."))
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    return output_root / f"truenas-config-{timestamp}.tar"


def load_api_key_from_file() -> str | None:
    key_path = BASE_DIR / ".truenas-api-key"
    try:
        if key_path.exists():
            return key_path.read_text(encoding="utf-8").strip() or None
    except OSError:
        return None
    return None


def load_vault_transit_settings(
    backup_verify_ssl: bool,
    output_file: Path,
) -> VaultTransitSettings | None:
    enabled = parse_bool(os.getenv("VAULT_TRANSIT_ENABLED"), default=False)
    if not enabled:
        return None

    address = os.getenv("VAULT_ADDR")
    token = os.getenv("VAULT_TOKEN")
    key_name = os.getenv("VAULT_TRANSIT_KEY")
    if not address or not token or not key_name:
        raise SystemExit(
            "Vault Transit enabled, but VAULT_ADDR, VAULT_TOKEN, and VAULT_TRANSIT_KEY are required"
        )

    verify_ssl = parse_bool(os.getenv("VAULT_VERIFY_SSL"), default=backup_verify_ssl)
    ciphertext_file = Path(
        os.getenv("VAULT_TRANSIT_OUTPUT_FILE", f"{output_file}.vault.json")
    )

    return VaultTransitSettings(
        address=address.rstrip("/"),
        token=token,
        key_name=key_name,
        mount_path=os.getenv("VAULT_TRANSIT_MOUNT", "transit").strip("/"),
        verify_ssl=verify_ssl,
        namespace=os.getenv("VAULT_NAMESPACE"),
        ciphertext_file=ciphertext_file,
        delete_plaintext=parse_bool(os.getenv("VAULT_TRANSIT_DELETE_PLAINTEXT"), default=True),
    )


def write_jsonl(path: Path, obj: dict) -> None:
    try:
        line = json.dumps(obj, separators=(",", ":"), default=str, ensure_ascii=False)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as file_obj:
            file_obj.write(line + "\n")
            file_obj.flush()
            try:
                os.fsync(file_obj.fileno())
            except OSError:
                pass
    except Exception as exc:
        try:
            print(f"[LOG ERROR] Could not write log: {exc}", file=sys.stderr)
        except Exception:
            pass


def log_event(
    log_file: Path,
    event: str,
    status: str,
    details: str | None = None,
    **extra: object,
) -> None:
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "pid": OS_PID,
        "event": event,
        "status": status,
        "host": HOST_NAME,
    }
    if details is not None:
        entry["details"] = details
    if extra:
        entry["extra"] = extra
    write_jsonl(log_file, entry)


def build_ssl_context(verify_ssl: bool) -> ssl.SSLContext:
    return ssl.create_default_context() if verify_ssl else ssl._create_unverified_context()


async def recv_json(ws: "websockets.ClientConnection") -> dict:
    raw_message = await asyncio.wait_for(ws.recv(), timeout=WEBSOCKET_MESSAGE_TIMEOUT)
    if not isinstance(raw_message, str):
        raise RuntimeError("Unexpected non-text WebSocket message")
    return json.loads(raw_message)


async def get_download_url(settings: Settings) -> tuple[int, str]:
    import websockets

    uri = f"wss://{settings.truenas_host}/websocket"

    async with websockets.connect(
        uri,
        ssl=build_ssl_context(settings.verify_ssl),
        open_timeout=WEBSOCKET_OPEN_TIMEOUT,
        close_timeout=WEBSOCKET_OPEN_TIMEOUT,
    ) as ws:
        await ws.send(
            json.dumps(
                {
                    "msg": "connect",
                    "version": "1",
                    "support": ["1"],
                }
            )
        )

        connect_resp = await recv_json(ws)
        if connect_resp.get("msg") != "connected":
            raise RuntimeError(f"Unexpected connect response: {connect_resp}")

        await ws.send(
            json.dumps(
                {
                    "msg": "method",
                    "method": "auth.login_with_api_key",
                    "params": [settings.api_key],
                    "id": "1",
                }
            )
        )

        auth_resp = await recv_json(ws)
        if auth_resp.get("msg") != "result" or auth_resp.get("id") != "1":
            raise RuntimeError(f"Unexpected auth response: {auth_resp}")
        if auth_resp.get("error"):
            raise RuntimeError(f"Auth failed: {auth_resp['error']}")

        await ws.send(
            json.dumps(
                {
                    "msg": "method",
                    "method": "core.download",
                    "params": [
                        "config.save",
                        [
                            {
                                "secretseed": True,
                                "pool_keys": True,
                                "root_authorized_keys": True,
                            }
                        ],
                        "backup.tar",
                    ],
                    "id": "2",
                }
            )
        )

        while True:
            response = await recv_json(ws)
            if response.get("msg") != "result" or response.get("id") != "2":
                continue
            if response.get("error"):
                raise RuntimeError(f"API error: {response['error']}")

            truenas_job_id, url = response["result"]
            return truenas_job_id, url


def download_backup_bytes(settings: Settings, url: str) -> bytes:
    import requests

    download_url = url if url.startswith("http") else f"https://{settings.truenas_host}{url}"
    chunks: list[bytes] = []

    with requests.get(
        download_url,
        verify=settings.verify_ssl,
        stream=True,
        timeout=REQUEST_TIMEOUT,
    ) as response:
        response.raise_for_status()
        for chunk in response.iter_content(chunk_size=8192):
            if chunk:
                chunks.append(chunk)

    return b"".join(chunks)


def write_plaintext_backup(output_file: Path, backup_bytes: bytes) -> int:
    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_bytes(backup_bytes)
    return len(backup_bytes)


def validate_backup_bytes(backup_bytes: bytes) -> int:
    size = len(backup_bytes)
    if size < MIN_BACKUP_SIZE_BYTES:
        raise RuntimeError(
            f"Backup file too small: {size} bytes (minimum {MIN_BACKUP_SIZE_BYTES})"
        )
    return size


def encrypt_bytes_with_vault_transit(
    vault_settings: VaultTransitSettings,
    plaintext: bytes,
    source_file: Path,
) -> tuple[Path, int]:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    import requests

    plaintext_size_bytes = len(plaintext)
    headers = {
        "X-Vault-Token": vault_settings.token,
        "Content-Type": "application/json",
    }
    if vault_settings.namespace:
        headers["X-Vault-Namespace"] = vault_settings.namespace

    endpoint = (
        f"{vault_settings.address}/v1/"
        f"{vault_settings.mount_path}/datakey/plaintext/{vault_settings.key_name}"
    )
    response = requests.post(
        endpoint,
        headers=headers,
        json={"bits": 256},
        verify=vault_settings.verify_ssl,
        timeout=REQUEST_TIMEOUT,
    )
    if not response.ok:
        response_text = response.text.strip()
        raise RuntimeError(
            "Vault Transit datakey request failed "
            f"(status={response.status_code}, endpoint={endpoint}, "
            f"plaintext_size_bytes={plaintext_size_bytes}, "
            f"response={response_text or '<empty>'})"
        )
    payload = response.json()
    wrapped_data_key = payload.get("data", {}).get("ciphertext")
    data_key_plaintext = payload.get("data", {}).get("plaintext")
    if not wrapped_data_key or not data_key_plaintext:
        raise RuntimeError(f"Vault Transit datakey response missing required fields: {payload}")

    key_bytes = base64.b64decode(data_key_plaintext)
    nonce = os.urandom(12)
    aesgcm = AESGCM(key_bytes)
    encrypted_payload = aesgcm.encrypt(nonce, plaintext, None)
    key_version = payload.get("data", {}).get("key_version")
    output_path = vault_settings.ciphertext_file

    envelope = {
        "encrypted_at": datetime.now(timezone.utc).isoformat(),
        "source_file": str(source_file),
        "source_size_bytes": plaintext_size_bytes,
        "vault_addr": vault_settings.address,
        "vault_transit_mount": vault_settings.mount_path,
        "vault_transit_key": vault_settings.key_name,
        "encryption_mode": "vault_transit_datakey_aesgcm",
        "aes_gcm_nonce": base64.b64encode(nonce).decode("ascii"),
        "encrypted_backup": base64.b64encode(encrypted_payload).decode("ascii"),
        "wrapped_data_key": wrapped_data_key,
    }
    if vault_settings.namespace:
        envelope["vault_namespace"] = vault_settings.namespace
    if key_version is not None:
        envelope["vault_key_version"] = key_version

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(envelope, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    return output_path, output_path.stat().st_size


async def main(args: argparse.Namespace) -> None:
    import urllib3

    settings = Settings.load(args)
    start_time = datetime.now(timezone.utc)
    truenas_job_id = None
    backup_bytes = None
    backup_filesize_bytes = None
    vault_ciphertext_file = None
    vault_ciphertext_size_bytes = None
    plaintext_backup_written = False
    vault_encryption_enabled = settings.vault_transit is not None
    vault_encryption_status = "pending" if vault_encryption_enabled else "disabled"
    status = "success"
    error_details = None

    print("[+] Requesting backup via WebSocket")

    if not settings.verify_ssl:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    if settings.vault_transit is not None and not settings.vault_transit.verify_ssl:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    try:
        log_event(
            settings.log_file,
            "config_backup_started",
            "started",
            truenas_host=settings.truenas_host,
            backup_file=str(settings.output_file),
            vault_transit_enabled=vault_encryption_enabled,
        )
        truenas_job_id, url = await get_download_url(settings)
        log_event(
            settings.log_file,
            "config_backup_download_started",
            "started",
            backup_file=str(settings.output_file),
            truenas_job_id=truenas_job_id,
        )
        backup_bytes = download_backup_bytes(settings, url)
        backup_filesize_bytes = validate_backup_bytes(backup_bytes)
        log_event(
            settings.log_file,
            "config_backup_download_completed",
            "success",
            backup_file=str(settings.output_file),
            backup_filesize_bytes=backup_filesize_bytes,
            truenas_job_id=truenas_job_id,
        )

        if settings.vault_transit is not None:
            vault_encryption_status = "started"
            log_event(
                settings.log_file,
                "vault_transit_encrypt_started",
                "started",
                backup_file=str(settings.output_file),
                ciphertext_file=str(settings.vault_transit.ciphertext_file),
                vault_addr=settings.vault_transit.address,
                vault_transit_mount=settings.vault_transit.mount_path,
                vault_transit_key=settings.vault_transit.key_name,
                truenas_job_id=truenas_job_id,
            )
            vault_ciphertext_file, vault_ciphertext_size_bytes = encrypt_bytes_with_vault_transit(
                settings.vault_transit,
                backup_bytes,
                settings.output_file,
            )
            if not settings.vault_transit.delete_plaintext:
                write_plaintext_backup(settings.output_file, backup_bytes)
                plaintext_backup_written = True
            vault_encryption_status = "success"
            log_event(
                settings.log_file,
                "vault_transit_encrypt_completed",
                "success",
                backup_file=str(settings.output_file),
                ciphertext_file=str(vault_ciphertext_file),
                ciphertext_size_bytes=vault_ciphertext_size_bytes,
                delete_plaintext=settings.vault_transit.delete_plaintext,
                plaintext_backup_written=plaintext_backup_written,
                truenas_job_id=truenas_job_id,
            )
        else:
            write_plaintext_backup(settings.output_file, backup_bytes)
            plaintext_backup_written = True

        if plaintext_backup_written:
            print(f"[+] Backup complete: {settings.output_file}")
        if vault_ciphertext_file is not None:
            print(f"[+] Vault Transit ciphertext written: {vault_ciphertext_file}")
    except Exception as exc:
        status = "error"
        error_details = str(exc)
        if settings.vault_transit is not None and vault_encryption_status == "started":
            vault_encryption_status = "error"
            log_event(
                settings.log_file,
                "vault_transit_encrypt_failed",
                "error",
                details=error_details,
                backup_file=str(settings.output_file),
                ciphertext_file=str(settings.vault_transit.ciphertext_file),
                truenas_job_id=truenas_job_id,
            )
        elif settings.vault_transit is not None and vault_encryption_status == "pending":
            vault_encryption_status = "skipped"
        log_event(
            settings.log_file,
            "config_backup_failed",
            "error",
            details=error_details,
            backup_file=str(settings.output_file),
            truenas_job_id=truenas_job_id,
            vault_transit_enabled=vault_encryption_enabled,
            vault_encryption_status=vault_encryption_status,
        )
        raise
    finally:
        end_time = datetime.now(timezone.utc)
        duration_ms = int((end_time - start_time).total_seconds() * 1000)
        log_entry = {
            "timestamp": end_time.isoformat(),
            "pid": OS_PID,
            "event": "config_backup",
            "status": status,
            "host": HOST_NAME,
            "duration_ms": duration_ms,
            "backup_file": str(settings.output_file),
            "plaintext_backup_written": plaintext_backup_written,
            "vault_transit_enabled": vault_encryption_enabled,
            "vault_encryption_status": vault_encryption_status,
        }

        if truenas_job_id is not None:
            log_entry["truenas_job_id"] = truenas_job_id
        if backup_filesize_bytes is not None:
            log_entry["backup_filesize_bytes"] = backup_filesize_bytes
        if vault_ciphertext_file is not None:
            log_entry["vault_ciphertext_file"] = str(vault_ciphertext_file)
        if vault_ciphertext_size_bytes is not None:
            log_entry["vault_ciphertext_size_bytes"] = vault_ciphertext_size_bytes
        if error_details:
            log_entry["error"] = error_details

        write_jsonl(settings.log_file, log_entry)


if __name__ == "__main__":
    asyncio.run(main(build_parser().parse_args()))
