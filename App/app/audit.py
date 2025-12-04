# app/audit.py
from datetime import datetime, timezone

LOG_FILE = "audit.log" 


def audit(message: str, level: str = "INFO"):
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S %Z")
    line = f"{timestamp} [{level}] {message}"

    print(line, flush=True)

    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(line + "\n")
