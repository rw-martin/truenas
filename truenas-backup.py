#!/usr/bin/env python3

import asyncio,json,ssl,requests,sys,os,socket,re,websockets, urllib3
from datetime import datetime, timezone
from pathlib import Path
from dotenv import load_dotenv

# load environment variables from .env (if present)
load_dotenv()

VERIFY_SSL = os.getenv("VERIFY_SSL", "false").strip().lower() in ("1", "true", "yes")
DISABLE_SSL_VERIFICATION = os.getenv("DISABLE_SSL_VERIFICATION", "false").strip().lower() in ("1", "true", "yes")
LOG_FILE = os.getenv("TRUENAS_LOG_FILE", os.path.join(sys.path[0], "truenas.jsonl"))
OS_PID = os.getpid()
HOST_NAME = socket.gethostname().split(".")[0]

def log_event(level, event, details=None, extra=None, timestamp=None):
    if timestamp is None:
        timestamp = datetime.now(timezone.utc).isoformat()  # ISO 8601 format with timezone info, in

    entry = {
        "timestamp": timestamp,
        "pid": OS_PID,
        "level": level,
        "event": event,
        "host": HOST_NAME        
    }

    if details is not None:
        entry["details"] = details

    if extra is not None:
        entry["extra"] = extra

    _write_jsonl(LOG_FILE, entry)

def _write_jsonl(path, obj):
    try:
        line = json.dumps(obj, separators=(",", ":"), default=str, ensure_ascii=False)
        # use append mode and fsync for durability
        with open(path, "a", encoding="utf-8") as f:
            f.write(line + "\n")
            f.flush()
            try:
                os.fsync(f.fileno())
            except Exception:
                # best-effort; don't raise on fsync failure
                pass
    except Exception as e:
        # avoid crashing the main program for logging failures
        try:
            print(f"[LOG ERROR] Could not write log: {e}", file=sys.stderr)
        except Exception:
            pass

########################################
# CONFIG
########################################
TRUENAS_HOST = os.getenv("TRUENAS_HOST", "truenas.local")
API_KEY = os.getenv("API_KEY")
OUTPUT_FILE_ROOT = os.getenv("OUTPUT_FILE_ROOT")
OUTPUT_FILE = os.getenv("OUTPUT_FILE")

if not OUTPUT_FILE:
    if OUTPUT_FILE_ROOT:
        OUTPUT_FILE = os.path.join(
            OUTPUT_FILE_ROOT,
            f"truenas-config-{datetime.now().strftime('%Y%m%d-%H%M%S')}.tar",
        )
    else:
        OUTPUT_FILE = f"./truenas-config-{datetime.now().strftime('%Y%m%d-%H%M%S')}.tar"


########################################
# LOAD API KEY
########################################
def load_api_key():
    global API_KEY
    if API_KEY:
        return API_KEY

    if not API_KEY:
        key_path = Path(sys.path[0]) / ".truenas-api-key"
        if key_path.exists():
            try:
                API_KEY = key_path.read_text(encoding="utf-8").strip()
            except Exception:
                pass  # Silent failure for file read

    if not API_KEY:
        raise SystemExit("API key missing; set API_KEY in .env or .truenas-api-key")

    # No logging here, as per simplified logging
    return API_KEY

########################################
# WEBSOCKET LOGIC (DDP PROTOCOL)
########################################
async def get_download_url():
    uri = f"wss://{TRUENAS_HOST}/websocket"

    ssl_context = ssl.create_default_context()
    if not VERIFY_SSL:
        ssl_context = ssl._create_unverified_context()

    async with websockets.connect(uri, ssl=ssl_context) as ws:

        # 1️⃣ Connect (DDP handshake)
        await ws.send(json.dumps({
            "msg": "connect",
            "version": "1",
            "support": ["1"]
        }))

        await ws.recv()  # consume server response

        # 2️⃣ Authenticate
        await ws.send(json.dumps({
            "msg": "method",
            "method": "auth.login_with_api_key",
            "params": [load_api_key()],
            "id": "1"
        }))

        auth_resp = json.loads(await ws.recv())

        if auth_resp.get("msg") == "result" and auth_resp.get("error"):
            raise Exception(f"Auth failed: {auth_resp['error']}")

        # 3️⃣ Request download
        await ws.send(json.dumps({
            "msg": "method",
            "method": "core.download",
            "params": [
                "config.save",
                [{
                    "secretseed": True,
                    "root_authorized_keys": True
                }],
                "backup.tar"
            ],
            "id": "2"
        }))

        # 4️⃣ Wait for response
        while True:
            response = json.loads(await ws.recv())

            if response.get("msg") == "result" and response.get("id") == "2":
                if response.get("error"):
                    raise Exception(f"API error: {response['error']}")

                job_id, url = response["result"]
                return job_id, url

########################################
# DOWNLOAD FILE
########################################
def download_file(url):
    if not url.startswith("http"):
        url = f"https://{TRUENAS_HOST}{url}"

    r = requests.get(url, verify=VERIFY_SSL, stream=True)

    if r.status_code != 200:
        raise Exception(f"Download failed: HTTP {r.status_code}")

    with open(OUTPUT_FILE, "wb") as f:
        for chunk in r.iter_content(chunk_size=8192):
            if chunk:
                f.write(chunk)

    try:
        size = os.path.getsize(OUTPUT_FILE)
    except Exception:
        size = None

########################################
# VALIDATION
########################################
def validate_file():
    size = os.path.getsize(OUTPUT_FILE)

    if size < 50000:
        raise Exception("Backup file too small")

########################################
# MAIN
########################################

async def main():
    start_time = datetime.now(timezone.utc)
    job_id = None
    filesize_bytes = None
    status = "success"
    error_details = None

    print("[+] Requesting backup via WebSocket")

    # suppress InsecureRequestWarning when VERIFY_SSL is disabled
    if os.getenv("DISABLE_SSL_VERIFICATION", "false").strip().lower() in ("1", "true", "yes"):
      urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    try:
        job_id, url = await get_download_url()

        # CRITICAL: download immediately
        download_file(url)

        validate_file()

        # Get file size
        try:
            filesize_bytes = os.path.getsize(OUTPUT_FILE)
        except Exception:
            filesize_bytes = None

        print(f"[+] Backup complete: {OUTPUT_FILE}")

    except Exception as e:
        status = "error"
        error_details = str(e)
        raise

    finally:
        # Calculate duration
        end_time = datetime.now(timezone.utc)
        duration_ms = int((end_time - start_time).total_seconds() * 1000)

        # Single comprehensive log entry
        log_entry = {
            "timestamp": end_time.isoformat(),
            "pid": OS_PID,
            "event": "config_backup",
            "status": status,
            "host": HOST_NAME,
            "duration_ms": duration_ms,
            "backup_file": OUTPUT_FILE
        }

        if job_id is not None:
            log_entry["job_id"] = job_id
        if filesize_bytes is not None:
            log_entry["filesize_bytes"] = filesize_bytes
        if error_details:
            log_entry["error"] = error_details

        _write_jsonl(LOG_FILE, log_entry)


if __name__ == "__main__":
    asyncio.run(main())