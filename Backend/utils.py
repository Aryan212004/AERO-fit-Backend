import random, uuid
from datetime import datetime, timezone
from typing import Optional

def doc(d: dict) -> dict:
    d.pop("_id", None)
    return d

def fmt_dt(dt) -> str:
    if isinstance(dt, datetime):
        return dt.isoformat()
    return str(dt) if dt else ""

def ensure_utc(dt) -> Optional[datetime]:
    if dt is None:
        return None
    if isinstance(dt, datetime) and dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt

def generate_code() -> str:
    chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    return "AF-" + "".join(random.choice(chars) for _ in range(4))

def generate_otp() -> str:
    return f"{random.randint(0, 999999):06d}"

def generate_reset_token() -> str:
    return str(uuid.uuid4())