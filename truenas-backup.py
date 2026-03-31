#!/usr/bin/env python3

import argparse
import asyncio
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
class Settings:
    truenas_host: str
    api_key: str
    verify_ssl: bool
    log_file: Path
    output_file: Path

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

            job_id, url = response["result"]
            return job_id, url


def download_file(settings: Settings, url: str) -> int:
    import requests

    download_url = url if url.startswith("http") else f"https://{settings.truenas_host}{url}"
    settings.output_file.parent.mkdir(parents=True, exist_ok=True)

    with requests.get(
        download_url,
        verify=settings.verify_ssl,
        stream=True,
        timeout=REQUEST_TIMEOUT,
    ) as response:
        response.raise_for_status()
        with settings.output_file.open("wb") as file_obj:
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    file_obj.write(chunk)

    return settings.output_file.stat().st_size


def validate_file(output_file: Path) -> int:
    size = output_file.stat().st_size
    if size < MIN_BACKUP_SIZE_BYTES:
        raise RuntimeError(
            f"Backup file too small: {size} bytes (minimum {MIN_BACKUP_SIZE_BYTES})"
        )
    return size


async def main(args: argparse.Namespace) -> None:
    import urllib3

    settings = Settings.load(args)
    start_time = datetime.now(timezone.utc)
    job_id = None
    filesize_bytes = None
    status = "success"
    error_details = None

    print("[+] Requesting backup via WebSocket")

    if not settings.verify_ssl:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    try:
        job_id, url = await get_download_url(settings)
        download_file(settings, url)
        filesize_bytes = validate_file(settings.output_file)
        print(f"[+] Backup complete: {settings.output_file}")
    except Exception as exc:
        status = "error"
        error_details = str(exc)
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
        }

        if job_id is not None:
            log_entry["job_id"] = job_id
        if filesize_bytes is not None:
            log_entry["filesize_bytes"] = filesize_bytes
        if error_details:
            log_entry["error"] = error_details

        write_jsonl(settings.log_file, log_entry)


if __name__ == "__main__":
    asyncio.run(main(build_parser().parse_args()))
