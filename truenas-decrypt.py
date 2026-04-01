#!/usr/bin/env python3

import argparse
import base64
import json
import os
import socket
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

try:
    from dotenv import load_dotenv
except ImportError:
    def load_dotenv() -> None:
        return None

load_dotenv()

TRUE_VALUES = {"1", "true", "yes", "on"}
REQUEST_TIMEOUT = (10, 60)
BASE_DIR = Path(sys.path[0])
OS_PID = os.getpid()
HOST_NAME = socket.gethostname().split(".")[0]


def parse_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in TRUE_VALUES


@dataclass(frozen=True)
class VaultSettings:
    address: str
    token: str
    mount_path: str
    verify_ssl: bool
    namespace: str | None


@dataclass(frozen=True)
class DecryptSettings:
    vault: VaultSettings
    log_file: Path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Decrypt a TrueNAS Vault envelope back into a tar backup."
    )
    parser.add_argument("envelope_file", help="Path to the .vault.json envelope file")
    parser.add_argument("--output-file", help="Path for the restored tar file")
    parser.add_argument("--vault-addr", help="Override VAULT_ADDR")
    parser.add_argument("--vault-token", help="Override VAULT_TOKEN")
    parser.add_argument("--vault-mount", help="Override VAULT_TRANSIT_MOUNT")
    parser.add_argument("--vault-namespace", help="Override VAULT_NAMESPACE")
    parser.add_argument(
        "--vault-verify-ssl",
        action="store_true",
        help="Enable Vault TLS certificate verification",
    )
    parser.add_argument(
        "--vault-insecure",
        action="store_true",
        help="Disable Vault TLS certificate verification",
    )
    return parser


def resolve_vault_verify_ssl(args: argparse.Namespace) -> bool:
    if args.vault_verify_ssl and args.vault_insecure:
        raise SystemExit("Choose either --vault-verify-ssl or --vault-insecure, not both")
    if args.vault_verify_ssl:
        return True
    if args.vault_insecure:
        return False
    return parse_bool(os.getenv("VAULT_VERIFY_SSL"), default=parse_bool(os.getenv("VERIFY_SSL"), default=False))


def load_vault_settings(args: argparse.Namespace) -> VaultSettings:
    address = args.vault_addr or os.getenv("VAULT_ADDR")
    token = args.vault_token or os.getenv("VAULT_TOKEN")
    if not address or not token:
        raise SystemExit("VAULT_ADDR and VAULT_TOKEN are required for decryption")

    return VaultSettings(
        address=address.rstrip("/"),
        token=token,
        mount_path=(args.vault_mount or os.getenv("VAULT_TRANSIT_MOUNT", "transit")).strip("/"),
        verify_ssl=resolve_vault_verify_ssl(args),
        namespace=args.vault_namespace or os.getenv("VAULT_NAMESPACE"),
    )


def load_decrypt_settings(args: argparse.Namespace) -> DecryptSettings:
    return DecryptSettings(
        vault=load_vault_settings(args),
        log_file=Path(os.getenv("TRUENAS_LOG_FILE", BASE_DIR / "truenas.jsonl")),
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


def decrypt_wrapped_data_key(
    vault_settings: VaultSettings,
    transit_key_name: str,
    wrapped_data_key: str,
) -> bytes:
    import requests

    headers = {
        "X-Vault-Token": vault_settings.token,
        "Content-Type": "application/json",
    }
    if vault_settings.namespace:
        headers["X-Vault-Namespace"] = vault_settings.namespace

    endpoint = (
        f"{vault_settings.address}/v1/"
        f"{vault_settings.mount_path}/decrypt/{transit_key_name}"
    )
    response = requests.post(
        endpoint,
        headers=headers,
        json={"ciphertext": wrapped_data_key},
        verify=vault_settings.verify_ssl,
        timeout=REQUEST_TIMEOUT,
    )
    if not response.ok:
        body = response.text.strip() or "<empty>"
        raise RuntimeError(
            f"Vault Transit decrypt failed (status={response.status_code}, "
            f"endpoint={endpoint}, response={body})"
        )

    payload = response.json()
    plaintext_b64 = payload.get("data", {}).get("plaintext")
    if not plaintext_b64:
        raise RuntimeError(f"Vault Transit decrypt response missing plaintext: {payload}")
    return base64.b64decode(plaintext_b64)


def resolve_output_file(args: argparse.Namespace, envelope_path: Path, envelope: dict) -> Path:
    if args.output_file:
        return Path(args.output_file)

    source_file = envelope.get("source_file")
    if source_file:
        return Path(source_file)

    if envelope_path.name.endswith(".vault.json"):
        return envelope_path.with_name(envelope_path.name.removesuffix(".vault.json"))
    return envelope_path.with_suffix(".tar")


def main() -> None:
    args = build_parser().parse_args()
    import urllib3
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    settings = load_decrypt_settings(args)
    if not settings.vault.verify_ssl:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    start_time = datetime.now(timezone.utc)
    envelope_path = Path(args.envelope_file)
    output_file = None
    restored_size_bytes = None
    transit_key_name = None
    vault_key_version = None
    status = "success"
    error_details = None

    print("[+] Restore started")
    
    log_event(
        settings.log_file,
        "config_restore_started",
        "started",
        envelope_file=str(envelope_path),
    )

    try:
        envelope = json.loads(envelope_path.read_text(encoding="utf-8"))
        output_file = resolve_output_file(args, envelope_path, envelope)
        transit_key_name = envelope.get("vault_transit_key")
        wrapped_data_key = envelope.get("wrapped_data_key")
        encrypted_backup = envelope.get("encrypted_backup")
        nonce_b64 = envelope.get("aes_gcm_nonce")
        vault_key_version = envelope.get("vault_key_version")
        if not transit_key_name or not wrapped_data_key or not encrypted_backup or not nonce_b64:
            raise SystemExit("Envelope missing required decryption fields")

        log_event(
            settings.log_file,
            "vault_transit_decrypt_started",
            "started",
            envelope_file=str(envelope_path),
            output_file=str(output_file),
            vault_transit_key=transit_key_name,
            vault_key_version=vault_key_version,
        )

        key_bytes = decrypt_wrapped_data_key(settings.vault, transit_key_name, wrapped_data_key)
        aesgcm = AESGCM(key_bytes)
        plaintext = aesgcm.decrypt(
            base64.b64decode(nonce_b64),
            base64.b64decode(encrypted_backup),
            None,
        )

        expected_size = envelope.get("source_size_bytes")
        if expected_size is not None and len(plaintext) != expected_size:
            raise RuntimeError(
                f"Decrypted size mismatch: got {len(plaintext)} bytes, expected {expected_size}"
            )

        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_bytes(plaintext)
        restored_size_bytes = len(plaintext)
        log_event(
            settings.log_file,
            "vault_transit_decrypt_completed",
            "success",
            envelope_file=str(envelope_path),
            output_file=str(output_file),
            restored_size_bytes=restored_size_bytes,
            vault_transit_key=transit_key_name,
            vault_key_version=vault_key_version,
        )
        print(f"[+] Restored backup: {output_file}")
    except Exception as exc:
        status = "error"
        error_details = str(exc)
        log_event(
            settings.log_file,
            "config_restore_failed",
            "error",
            details=error_details,
            envelope_file=str(envelope_path),
            output_file=str(output_file) if output_file is not None else None,
            vault_transit_key=transit_key_name,
            vault_key_version=vault_key_version,
        )
        raise
    finally:
        end_time = datetime.now(timezone.utc)
        duration_ms = int((end_time - start_time).total_seconds() * 1000)
        summary = {
            "timestamp": end_time.isoformat(),
            "pid": OS_PID,
            "event": "config_restore",
            "status": status,
            "host": HOST_NAME,
            "duration_ms": duration_ms,
            "envelope_file": str(envelope_path),
        }
        if output_file is not None:
            summary["output_file"] = str(output_file)
        if restored_size_bytes is not None:
            summary["restored_size_bytes"] = restored_size_bytes
        if transit_key_name is not None:
            summary["vault_transit_key"] = transit_key_name
        if vault_key_version is not None:
            summary["vault_key_version"] = vault_key_version
        if error_details:
            summary["error"] = error_details
        write_jsonl(settings.log_file, summary)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"[!] Decryption failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
