# Patch missing pkg_resources for razorpay on Render
try:
    from pkg_resources import DistributionNotFound
except ImportError:
    import types, sys
    pkg_resources = types.ModuleType("pkg_resources")
    pkg_resources.get_distribution = lambda x: type("D", (), {"version": "0.0.0"})()
    pkg_resources.DistributionNotFound = Exception
    sys.modules["pkg_resources"] = pkg_resources

import os, sys, json, re, bcrypt, uuid, base64, traceback, threading, time, asyncio
from datetime import datetime, timezone, timedelta
from typing import Optional
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import razorpay
import hmac
import hashlib
import requests as http_requests
import google.auth.transport.requests
from google.oauth2 import service_account

# ── Load .env for local dev (no-op on Render) ─────────────────────────────────
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# ══════════════════════════════════════════════════════════════════════════════
#  CONFIG
# ══════════════════════════════════════════════════════════════════════════════

def _require(key: str) -> str:
    val = os.environ.get(key, "").strip()
    if not val:
        print(f"❌  FATAL: environment variable '{key}' is missing or empty", flush=True)
        sys.exit(1)
    return val

GEMINI_API_KEY     = _require("GEMINI_API_KEY")
MONGO_URI          = _require("MONGO_URI")
CLOUDINARY_CLOUD   = _require("CLOUDINARY_CLOUD_NAME")
CLOUDINARY_API_KEY = _require("CLOUDINARY_API_KEY")
CLOUDINARY_SECRET  = _require("CLOUDINARY_API_SECRET")
RAZORPAY_KEY_ID     = _require("RAZORPAY_KEY_ID")
RAZORPAY_KEY_SECRET = _require("RAZORPAY_KEY_SECRET")

FIREBASE_PROJECT_ID  = os.environ.get("FIREBASE_PROJECT_ID", "").strip()
FIREBASE_CREDS_PATH  = "/etc/secrets/firebase-service-account.json"

SCAN_LIMIT           = int(os.environ.get("SCAN_LIMIT",           "10"))
MAX_CONCURRENT_SCANS = int(os.environ.get("MAX_CONCURRENT_SCANS", "50"))
SCAN_QUEUE_TIMEOUT_S = int(os.environ.get("SCAN_QUEUE_TIMEOUT_S", "60"))
MAX_QUEUE_DEPTH      = int(os.environ.get("MAX_QUEUE_DEPTH",      "200"))

ALPHA_USERNAME = os.environ.get("ALPHA_USERNAME", "superadmin").strip()
ALPHA_PASSWORD = os.environ.get("ALPHA_PASSWORD", "aerofit_alpha_2025").strip()

PLATFORM_SHARE_PCT = 40
GYM_SHARE_PCT      = 60

INDIE_BASE_PRICE   = float(os.environ.get("INDIE_BASE_PRICE",  "159"))  # ₹/month
INDIE_DISCOUNT_PCT = float(os.environ.get("INDIE_DISCOUNT_PCT", "1"))   # 1% per extra month

razorpay_client = razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET))
print(f"✅  Razorpay configured → key {RAZORPAY_KEY_ID[:12]}…", flush=True)

# ══════════════════════════════════════════════════════════════════════════════
#  MONGODB
# ══════════════════════════════════════════════════════════════════════════════

from pymongo import MongoClient, DESCENDING
from pymongo.collection import Collection

_mongo_client: MongoClient = MongoClient(MONGO_URI)
_db_name = MONGO_URI.rsplit("/", 1)[-1].split("?")[0].strip() or "aerofitdb"
mdb = _mongo_client[_db_name]

col_users:       Collection = mdb["users"]
col_meals:       Collection = mdb["meals"]
col_banners:     Collection = mdb["banners"]
col_notifs:      Collection = mdb["notifications"]
col_scan_limits: Collection = mdb["scan_limits"]
col_gyms:        Collection = mdb["platform_gyms"]
col_gym_admins:  Collection = mdb["platform_gym_admins"]
col_user_ids:    Collection = mdb["gym_user_ids"]
col_invoices:    Collection = mdb["invoices"]
col_payments:    Collection = mdb["indie_payments"]

# ── Indexes ───────────────────────────────────────────────────────────────────
col_users.create_index("email", unique=True)
col_users.create_index([("indie_plan", 1), ("indie_expires_at", 1)])
col_meals.create_index([("email", 1), ("logged_at", DESCENDING)])
col_banners.create_index("created_at")
col_banners.create_index([("gym_id", 1), ("created_at", DESCENDING)])
col_notifs.create_index("sent_at")
col_notifs.create_index([("gym_id", 1), ("sent_at", DESCENDING)])
col_scan_limits.create_index([("email", 1), ("date", 1)], unique=True)
col_gyms.create_index("gym_id", unique=True)
col_gyms.create_index("admin_email")
col_gym_admins.create_index("admin_id", unique=True)
col_gym_admins.create_index("email", unique=True)
col_gym_admins.create_index("gym_id")
col_user_ids.create_index([("gym_id", 1), ("code", 1)], unique=True)
col_user_ids.create_index("code")
col_user_ids.create_index([("status", 1), ("expires_at", 1)])
col_invoices.create_index([("gym_id", 1), ("created_at", DESCENDING)])
col_invoices.create_index("invoice_id", unique=True)
col_invoices.create_index("status")
col_payments.create_index("order_id", unique=True)
col_payments.create_index("payment_id")
col_payments.create_index("email")
col_payments.create_index([("email", 1), ("status", 1)])

print(f"✅  MongoDB connected → {_db_name}", flush=True)

# ══════════════════════════════════════════════════════════════════════════════
#  CLOUDINARY
# ══════════════════════════════════════════════════════════════════════════════

import cloudinary
import cloudinary.uploader

cloudinary.config(
    cloud_name = CLOUDINARY_CLOUD,
    api_key    = CLOUDINARY_API_KEY,
    api_secret = CLOUDINARY_SECRET,
    secure     = True,
)
print("✅  Cloudinary configured", flush=True)

# ══════════════════════════════════════════════════════════════════════════════
#  GEMINI
# ══════════════════════════════════════════════════════════════════════════════

from google import genai
from google.genai import types

gemini_client       = genai.Client(api_key=GEMINI_API_KEY)
GEMINI_MDL_PRIMARY  = "gemini-2.5-flash-lite"
GEMINI_MDL_FALLBACK = "gemini-2.5-flash"
print(f"✅  Gemini ready → {GEMINI_MDL_PRIMARY}", flush=True)

# ══════════════════════════════════════════════════════════════════════════════
#  CONCURRENCY CONTROLS
# ══════════════════════════════════════════════════════════════════════════════

_gemini_semaphore    = asyncio.Semaphore(MAX_CONCURRENT_SCANS)
_user_scan_locks:    dict[str, asyncio.Lock] = {}
_user_locks_meta:    dict[str, float]        = {}
_locks_registry_lock = asyncio.Lock()

async def _get_user_lock(email: str) -> asyncio.Lock:
    async with _locks_registry_lock:
        if email not in _user_scan_locks:
            _user_scan_locks[email] = asyncio.Lock()
        _user_locks_meta[email] = time.monotonic()
        return _user_scan_locks[email]

async def _cleanup_stale_locks():
    async with _locks_registry_lock:
        stale_cutoff = time.monotonic() - 600
        stale = [e for e, t in _user_locks_meta.items()
                 if t < stale_cutoff and not _user_scan_locks[e].locked()]
        for e in stale:
            del _user_scan_locks[e]
            del _user_locks_meta[e]
        if stale:
            print(f"🧹  Cleaned up {len(stale)} stale user lock(s)", flush=True)

print(f"✅  Concurrency controls ready → {MAX_CONCURRENT_SCANS} slots / {MAX_QUEUE_DEPTH} max queue depth", flush=True)

# ══════════════════════════════════════════════════════════════════════════════
#  BACKGROUND THREADS
# ══════════════════════════════════════════════════════════════════════════════

def _keep_alive():
    """Pings the server every 5 min to prevent Render free-tier sleep."""
    time.sleep(60)
    while True:
        try:
            import requests as _req
            _req.get("https://aero-fit-backend.onrender.com/health", timeout=10)
            print("✅  Keep-alive ping sent", flush=True)
        except Exception as e:
            print(f"⚠️  Keep-alive failed: {e}", flush=True)
        time.sleep(300)


def _run_expiry_job():
    """
    Hourly job — two tasks:
      1. Expire gym memberships whose user-ID expires_at has passed.
      2. Expire indie users whose indie_expires_at has passed.
    """
    time.sleep(30)
    while True:
        try:
            now = datetime.now(timezone.utc)

            # ── 1. Gym memberships ────────────────────────────────────────────
            expired_ids = list(col_user_ids.find({
                "status":     "used",
                "expires_at": {"$lte": now},
            }))

            if expired_ids:
                print(f"⏰  Expiry job: processing {len(expired_ids)} expired gym User ID(s)", flush=True)

            for uid_doc in expired_ids:
                code    = uid_doc.get("code")
                gym_id  = uid_doc.get("gym_id")
                used_by = uid_doc.get("used_by")

                if used_by:
                    col_users.update_one(
                        {"email": used_by},
                        {"$set": {
                            "membership_expired":    True,
                            "membership_expired_at": now,
                            "gym_id":                None,
                        }}
                    )
                    print(f"   ↳ Expired gym user: {used_by}", flush=True)

                col_user_ids.delete_one({"gym_id": gym_id, "code": code})
                col_gyms.update_one(
                    {"gym_id": gym_id, "members": {"$gt": 0}},
                    {"$inc": {"members": -1}}
                )
                print(f"   ↳ Deleted User ID: {code} — gym: {gym_id}", flush=True)

            # ── 2. Indie plan expirations ─────────────────────────────────────
            expired_indie = list(col_users.find({
                "indie_plan":         True,
                "membership_expired": {"$ne": True},
                "indie_expires_at":   {"$lte": now},
            }))

            if expired_indie:
                print(f"⏰  Expiry job: processing {len(expired_indie)} expired indie user(s)", flush=True)

            for u in expired_indie:
                col_users.update_one(
                    {"email": u["email"]},
                    {"$set": {
                        "membership_expired":    True,
                        "membership_expired_at": now,
                    }}
                )
                print(f"   ↳ Expired indie user: {u['email']}", flush=True)

        except Exception as e:
            print(f"⚠️  Expiry job error: {e}", flush=True)

        time.sleep(3600)


threading.Thread(target=_keep_alive,     daemon=True).start()
threading.Thread(target=_run_expiry_job, daemon=True).start()
print("✅  Background threads started (keep-alive + expiry job)", flush=True)

# ══════════════════════════════════════════════════════════════════════════════
#  FASTAPI APP
# ══════════════════════════════════════════════════════════════════════════════

app = FastAPI(title="AERO-FIT API", version="17.0.0")

ALLOWED_ORIGINS = [
    "http://localhost:5173", "http://localhost:5174", "http://localhost:3000",
    "http://127.0.0.1:5173", "http://127.0.0.1:5174", "http://127.0.0.1:3000",
    # "https://your-admin-dashboard.vercel.app",  ← uncomment and add your URL
]

app.add_middleware(
    CORSMiddleware,
    allow_origins     = ALLOWED_ORIGINS,
    allow_credentials = False,
    allow_methods     = ["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
    allow_headers     = ["*"],
    expose_headers    = ["*", "Retry-After"],
    max_age           = 3600,
)

@app.options("/{rest_of_path:path}")
async def preflight_handler(request: Request, rest_of_path: str):
    return JSONResponse(
        content={},
        headers={
            "Access-Control-Allow-Origin":  request.headers.get("origin", "*"),
            "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS, PATCH",
            "Access-Control-Allow-Headers": "*",
            "Access-Control-Max-Age":       "3600",
        },
    )

# ══════════════════════════════════════════════════════════════════════════════
#  HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def _strip_b64_prefix(b64: str) -> str:
    return b64.split(",", 1)[1].strip() if "," in b64 else b64.strip()

def _b64_to_part(b64: str, mime: str = "image/jpeg") -> types.Part:
    if not b64:
        raise ValueError("Empty image data")
    return types.Part.from_bytes(
        data=base64.b64decode(_strip_b64_prefix(b64)), mime_type=mime)

def _is_overload_error(e: Exception) -> bool:
    msg = str(e).lower()
    return any(k in msg for k in ["503", "unavailable", "high demand", "resource_exhausted", "429"])

def _ask_gemini(parts: list, prompt: str, max_retries: int = 3) -> str:
    all_parts = list(parts) + [types.Part.from_text(text=prompt)]
    contents  = [types.Content(role="user", parts=all_parts)]
    for model in [GEMINI_MDL_PRIMARY, GEMINI_MDL_FALLBACK]:
        for attempt in range(max_retries):
            try:
                response = gemini_client.models.generate_content(model=model, contents=contents)
                return response.text
            except Exception as e:
                if _is_overload_error(e):
                    if attempt < max_retries - 1:
                        time.sleep(2 ** attempt)
                        continue
                    break
                else:
                    raise
    raise HTTPException(503, "AI is currently busy. Please try again in a few seconds.")

def _extract_json(text: str) -> dict:
    text = re.sub(r"```(?:json)?", "", text).strip()
    m    = re.search(r"\{.*\}", text, re.DOTALL)
    if not m:
        raise ValueError(f"No JSON found: {text[:300]}")
    return json.loads(m.group())

def _safe_int(val, default: int = 0) -> int:
    try:
        return int(float(str(val).replace("~", "").strip()))
    except Exception:
        return default

def _doc(d: dict) -> dict:
    d.pop("_id", None)
    return d

def _fmt_dt(dt) -> str:
    if isinstance(dt, datetime):
        return dt.isoformat()
    return str(dt) if dt else ""

def upload_image(base64_str: str, folder: str, public_id: str = None) -> str:
    if not base64_str:
        return ""
    raw      = _strip_b64_prefix(base64_str)
    data_uri = f"data:image/jpeg;base64,{raw}"
    result   = cloudinary.uploader.upload(
        data_uri,
        folder        = folder,
        public_id     = public_id or str(uuid.uuid4()),
        overwrite     = True,
        resource_type = "image",
        format        = "jpg",
        transformation= [{"quality": "auto", "fetch_format": "auto"}],
    )
    return result.get("secure_url", "")

def _ensure_utc(dt) -> Optional[datetime]:
    if dt is None:
        return None
    if isinstance(dt, datetime) and dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt

def _check_and_increment_scan_limit(email: str) -> int:
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    query = {"email": email, "date": today}
    doc   = col_scan_limits.find_one(query)
    if doc:
        count = doc.get("count", 0)
        if count >= SCAN_LIMIT:
            raise HTTPException(429, f"Daily scan limit reached ({SCAN_LIMIT}/day). Try again tomorrow!")
        col_scan_limits.update_one(query, {"$inc": {"count": 1}})
        return SCAN_LIMIT - (count + 1)
    col_scan_limits.insert_one({**query, "count": 1})
    return SCAN_LIMIT - 1

def _generate_code() -> str:
    chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    return "AF-" + "".join(__import__("random").choice(chars) for _ in range(4))

def _indie_pricing(months: int) -> dict:
    months       = max(1, min(months, 12))
    discount_pct = (months - 1) * INDIE_DISCOUNT_PCT
    gross_inr    = round(INDIE_BASE_PRICE * months, 2)
    discount_inr = round(gross_inr * discount_pct / 100, 2)
    final_inr    = round(gross_inr - discount_inr, 2)
    return {
        "months":       months,
        "base_price":   INDIE_BASE_PRICE,
        "gross_inr":    gross_inr,
        "discount_pct": discount_pct,
        "discount_inr": discount_inr,
        "final_inr":    final_inr,
        "final_paise":  int(final_inr * 100),
    }

def _verify_hmac(order_id: str, payment_id: str, signature: str) -> bool:
    msg      = f"{order_id}|{payment_id}"
    expected = hmac.new(
        RAZORPAY_KEY_SECRET.encode(),
        msg.encode(),
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(expected, signature)

# ══════════════════════════════════════════════════════════════════════════════
#  BILLING HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def _calc_invoice_splits(price_per_user: float, member_count: int) -> dict:
    gross           = round(price_per_user * member_count, 2)
    platform_amount = round(gross * PLATFORM_SHARE_PCT / 100, 2)
    gym_amount      = round(gross * GYM_SHARE_PCT / 100, 2)
    return {
        "gross":           gross,
        "platform_amount": platform_amount,
        "gym_amount":      gym_amount,
        "platform_pct":    PLATFORM_SHARE_PCT,
        "gym_pct":         GYM_SHARE_PCT,
    }

def _invoice_number() -> str:
    now    = datetime.now(timezone.utc)
    suffix = str(uuid.uuid4())[:4].upper()
    return f"AF-INV-{now.strftime('%Y%m')}-{suffix}"

# ══════════════════════════════════════════════════════════════════════════════
#  CASCADE GYM DELETE HELPER
# ══════════════════════════════════════════════════════════════════════════════

def _cascade_delete_gym(gym_id: str) -> dict:
    """
    Permanently deletes a gym and ALL associated data:
      - gym record
      - gym admin accounts
      - all user accounts registered under this gym
      - their meal logs
      - their scan limit records
      - all User ID codes for this gym
      - all invoices for this gym
      - all banners for this gym
      - all notifications for this gym

    Returns a summary dict of deleted counts for logging.
    """
    # ── 1. Collect all member emails before deleting anything ─────────────────
    member_emails = [
        u["email"] for u in col_users.find({"gym_id": gym_id}, {"email": 1})
    ]

    # ── 2. Delete gym members (users) ─────────────────────────────────────────
    users_result = col_users.delete_many({"gym_id": gym_id})

    # ── 3. Delete meal logs for those members ─────────────────────────────────
    meals_deleted = 0
    if member_emails:
        meals_result  = col_meals.delete_many({"email": {"$in": member_emails}})
        meals_deleted = meals_result.deleted_count

    # ── 4. Delete scan limits for those members ───────────────────────────────
    scans_deleted = 0
    if member_emails:
        scans_result  = col_scan_limits.delete_many({"email": {"$in": member_emails}})
        scans_deleted = scans_result.deleted_count

    # ── 5. Delete all User ID codes for this gym ──────────────────────────────
    user_ids_result = col_user_ids.delete_many({"gym_id": gym_id})

    # ── 6. Delete all invoices for this gym ───────────────────────────────────
    invoices_result = col_invoices.delete_many({"gym_id": gym_id})

    # ── 7. Delete all banners for this gym ────────────────────────────────────
    banners_result = col_banners.delete_many({"gym_id": gym_id})

    # ── 8. Delete all notifications for this gym ──────────────────────────────
    notifs_result = col_notifs.delete_many({"gym_id": gym_id})

    # ── 9. Delete gym admin accounts ──────────────────────────────────────────
    admins_result = col_gym_admins.delete_many({"gym_id": gym_id})

    # ── 10. Delete the gym record itself ──────────────────────────────────────
    col_gyms.delete_one({"gym_id": gym_id})

    summary = {
        "gym_id":           gym_id,
        "users_deleted":    users_result.deleted_count,
        "meals_deleted":    meals_deleted,
        "scans_deleted":    scans_deleted,
        "user_ids_deleted": user_ids_result.deleted_count,
        "invoices_deleted": invoices_result.deleted_count,
        "banners_deleted":  banners_result.deleted_count,
        "notifs_deleted":   notifs_result.deleted_count,
        "admins_deleted":   admins_result.deleted_count,
    }
    print(
        f"🗑️  Cascade gym delete → {gym_id} | "
        f"users={summary['users_deleted']} meals={summary['meals_deleted']} "
        f"scans={summary['scans_deleted']} user_ids={summary['user_ids_deleted']} "
        f"invoices={summary['invoices_deleted']} banners={summary['banners_deleted']} "
        f"notifs={summary['notifs_deleted']} admins={summary['admins_deleted']}",
        flush=True,
    )
    return summary

# ══════════════════════════════════════════════════════════════════════════════
#  FCM PUSH SENDER
# ══════════════════════════════════════════════════════════════════════════════

def _send_fcm_push(gym_id: str, title: str, body: str, data: dict = {}):
    """
    Sends OS-level push notification to all devices subscribed
    to topic gym_{gym_id}. Works when app is fully closed.
    """
    try:
        if not FIREBASE_PROJECT_ID:
            print("⚠️  FIREBASE_PROJECT_ID not set — skipping push", flush=True)
            return
        if not os.path.exists(FIREBASE_CREDS_PATH):
            print(f"⚠️  Firebase creds not found at {FIREBASE_CREDS_PATH}", flush=True)
            return

        creds = service_account.Credentials.from_service_account_file(
            FIREBASE_CREDS_PATH,
            scopes=["https://www.googleapis.com/auth/firebase.messaging"],
        )
        creds.refresh(google.auth.transport.requests.Request())

        resp = http_requests.post(
            f"https://fcm.googleapis.com/v1/projects/{FIREBASE_PROJECT_ID}/messages:send",
            headers={
                "Authorization": f"Bearer {creds.token}",
                "Content-Type":  "application/json",
            },
            json={
                "message": {
                    "topic": f"gym_{gym_id}",
                    "notification": {
                        "title": title,
                        "body":  body,
                    },
                    "data": {k: str(v) for k, v in data.items()},
                    "android": {
                        "priority": "high",
                        "notification": {
                            "channel_id":           "aerofit_channel",
                            "default_sound":        True,
                            "notification_priority": "PRIORITY_HIGH",
                        },
                    },
                    "apns": {
                        "headers": {"apns-priority": "10"},
                        "payload": {
                            "aps": {
                                "sound":             "default",
                                "badge":             1,
                                "content-available": 1,
                            }
                        },
                    },
                }
            },
            timeout=10,
        )

        result = resp.json()
        if resp.status_code == 200:
            print(f"✅  FCM push sent → gym={gym_id}  title='{title}'", flush=True)
        else:
            print(f"⚠️  FCM error {resp.status_code}: {result}", flush=True)

    except Exception as e:
        print(f"⚠️  FCM push failed: {e}", flush=True)

# ══════════════════════════════════════════════════════════════════════════════
#  PYDANTIC MODELS
# ══════════════════════════════════════════════════════════════════════════════

class AdminLogin(BaseModel):
    username: str
    password: str

class AlphaLogin(BaseModel):
    username: str
    password: str

class AddUserRequest(BaseModel):
    name:      str
    email:     str
    password:  str
    weight_kg: float
    height_cm: float
    gym_id:    Optional[str] = None
    user_id:   Optional[str] = None

class UserLogin(BaseModel):
    email:    str
    password: str

class UserUpdate(BaseModel):
    name:      Optional[str]   = None
    weight_kg: Optional[float] = None
    height_cm: Optional[float] = None

class MealRequest(BaseModel):
    image_base64: str
    email:        str = ""

class LogMealRequest(BaseModel):
    email:        str
    name:         str
    kcal:         int
    protein:      int
    carbs:        int
    fat:          int
    fiber:        int
    serving_size: str
    image_base64: Optional[str] = ""

class BannerCreate(BaseModel):
    title:        str
    screen:       str           = "home"
    status:       str           = "active"
    expires_at:   Optional[str] = None
    deep_link:    Optional[str] = None
    image_base64: Optional[str] = None
    gym_id:       str

class NotificationCreate(BaseModel):
    title:        str
    body:         str
    type:         str       = "general"
    segments:     list[str] = ["all"]
    deep_link:    Optional[str] = None
    scheduled_at: Optional[str] = None
    gym_id:       str

class GymCreate(BaseModel):
    name:           str
    city:           str
    plan:           str   = "Starter"
    admin_email:    str
    admin_name:     str   = "Admin"
    admin_password: str   = ""
    price_per_user: float = 0.0

class GymUpdate(BaseModel):
    name:           Optional[str]   = None
    city:           Optional[str]   = None
    plan:           Optional[str]   = None
    status:         Optional[str]   = None
    members:        Optional[int]   = None
    revenue:        Optional[int]   = None
    price_per_user: Optional[float] = None

class GymAdminUpdate(BaseModel):
    name:   Optional[str] = None
    email:  Optional[str] = None
    status: Optional[str] = None

class ValidateUserIdRequest(BaseModel):
    user_id: str

class GenerateUserIdsRequest(BaseModel):
    count:       int = 1
    plan_months: int = 1

class InvoiceCreate(BaseModel):
    gym_id:       str
    period:       str
    member_count: int
    notes:        Optional[str] = ""

class InvoiceStatusUpdate(BaseModel):
    status:      str
    paid_at:     Optional[str] = None
    payment_ref: Optional[str] = None

class InvoiceAlert(BaseModel):
    gym_id:     str
    message:    str
    alert_type: str = "payment_reminder"

class UpdateUserIdPlan(BaseModel):
    plan_months: int

class FcmTokenUpdate(BaseModel):
    fcm_token: str
    gym_id:    str

# ── Indie (independent) payment models ───────────────────────────────────────
class IndieOrderRequest(BaseModel):
    months:    int
    email:     str
    name:      str
    password:  str
    weight_kg: float
    height_cm: float

class IndieVerifyRequest(BaseModel):
    razorpay_order_id:   str
    razorpay_payment_id: str
    razorpay_signature:  str

class IndieRenewOrderRequest(BaseModel):
    email:    str
    password: str
    months:   int

# ══════════════════════════════════════════════════════════════════════════════
#  ROUTES — HEALTH
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/health")
def health():
    return {
        "status":         "ok",
        "version":        "17.0.0",
        "db":             "mongodb",
        "ai":             GEMINI_MDL_PRIMARY,
        "max_concurrent": MAX_CONCURRENT_SCANS,
        "active_scans":   MAX_CONCURRENT_SCANS - _gemini_semaphore._value,
    }

# ══════════════════════════════════════════════════════════════════════════════
#  ROUTES — ALPHA ADMIN AUTH
# ══════════════════════════════════════════════════════════════════════════════

@app.post("/alpha/login")
def alpha_login(req: AlphaLogin):
    if req.username != ALPHA_USERNAME or req.password != ALPHA_PASSWORD:
        raise HTTPException(401, "Invalid alpha admin credentials")
    return {"status": "ok", "role": "alpha"}

# ══════════════════════════════════════════════════════════════════════════════
#  ROUTES — GYM ADMIN AUTH
# ══════════════════════════════════════════════════════════════════════════════

@app.post("/gym-admin/login")
def gym_admin_login(req: AdminLogin):
    email = req.username.strip().lower()
    adm   = col_gym_admins.find_one({"email": email})
    if not adm:
        raise HTTPException(401, "Invalid credentials")
    if adm.get("status") == "inactive":
        raise HTTPException(403, "This admin account has been deactivated")
    if not bcrypt.checkpw(req.password.encode(), adm["password"].encode()):
        raise HTTPException(401, "Invalid credentials")
    return {
        "status":   "ok",
        "role":     "gym_admin",
        "admin_id": adm["admin_id"],
        "gym_id":   adm["gym_id"],
        "gym_name": adm["gym_name"],
        "name":     adm["name"],
        "email":    adm["email"],
    }

# ══════════════════════════════════════════════════════════════════════════════
#  ROUTES — PLATFORM STATS
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/alpha/stats")
def platform_stats():
    gyms             = list(col_gyms.find())
    paid_invoices    = list(col_invoices.find({"status": "paid"}))
    platform_earned  = sum(inv.get("platform_amount", 0) for inv in paid_invoices)
    pending_invoices = list(col_invoices.find({"status": {"$in": ["pending", "overdue"]}}))
    pending_amount   = sum(inv.get("gross", 0) for inv in pending_invoices)

    indie_payments  = list(col_payments.find({"status": "paid"}))
    indie_revenue   = sum(p.get("amount_inr", 0) for p in indie_payments)
    indie_users     = col_users.count_documents({"indie_plan": True, "membership_expired": {"$ne": True}})

    return {
        "total_gyms":       len(gyms),
        "active_gyms":      sum(1 for g in gyms if g.get("status") == "active"),
        "trial_gyms":       sum(1 for g in gyms if g.get("status") == "trial"),
        "pro_gyms":         sum(1 for g in gyms if g.get("plan") == "Pro"),
        "total_members":    sum(g.get("members", 0) for g in gyms),
        "total_revenue":    sum(g.get("revenue", 0) for g in gyms),
        "platform_earned":  platform_earned,
        "pending_amount":   pending_amount,
        "paid_invoices":    len(paid_invoices),
        "pending_invoices": len(pending_invoices),
        "overdue_invoices": sum(1 for inv in pending_invoices if inv.get("status") == "overdue"),
        "indie_users":      indie_users,
        "indie_revenue":    indie_revenue,
    }

# ══════════════════════════════════════════════════════════════════════════════
#  ROUTES — GYMS (alpha admin)
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/alpha/gyms")
def list_gyms():
    docs = list(col_gyms.find().sort("created_at", DESCENDING))
    return [_doc(d) for d in docs]

@app.post("/alpha/gyms")
def create_gym(req: GymCreate):
    admin_email = req.admin_email.strip().lower()
    if col_gym_admins.find_one({"email": admin_email}):
        raise HTTPException(409, "An admin with that email already exists")

    gym_id   = "gym_" + str(uuid.uuid4())[:8]
    admin_id = "adm_" + str(uuid.uuid4())[:8]
    raw_pw   = req.admin_password.strip() or re.sub(r"[^a-z0-9]", "", req.name.lower()) + "2025"
    now      = datetime.now(timezone.utc)

    col_gyms.insert_one({
        "gym_id":         gym_id,
        "name":           req.name.strip(),
        "city":           req.city.strip(),
        "plan":           req.plan,
        "status":         "trial" if req.plan == "Trial" else "active",
        "members":        0,
        "revenue":        0,
        "price_per_user": req.price_per_user,
        "admin_email":    admin_email,
        "admin_id":       admin_id,
        "created_at":     now,
    })

    hashed = bcrypt.hashpw(raw_pw.encode(), bcrypt.gensalt()).decode()
    col_gym_admins.insert_one({
        "admin_id":   admin_id,
        "gym_id":     gym_id,
        "gym_name":   req.name.strip(),
        "name":       req.admin_name.strip(),
        "email":      admin_email,
        "password":   hashed,
        "status":     "active",
        "created_at": now,
    })

    print(f"✅  Gym created → {gym_id}  admin → {admin_email}  price_per_user → ₹{req.price_per_user}", flush=True)
    return {
        "status":         "created",
        "gym_id":         gym_id,
        "admin_id":       admin_id,
        "admin_email":    admin_email,
        "admin_password": raw_pw,
        "price_per_user": req.price_per_user,
    }

@app.get("/alpha/gyms/{gym_id}")
def get_gym(gym_id: str):
    gym = col_gyms.find_one({"gym_id": gym_id})
    if not gym:
        raise HTTPException(404, "Gym not found")
    gym   = _doc(gym)
    admin = col_gym_admins.find_one({"gym_id": gym_id})
    if admin:
        admin = _doc(admin)
        admin.pop("password", None)
        gym["admin"] = admin
    return gym

@app.patch("/alpha/gyms/{gym_id}")
def update_gym(gym_id: str, req: GymUpdate):
    if not col_gyms.find_one({"gym_id": gym_id}):
        raise HTTPException(404, "Gym not found")
    update: dict = {"updated_at": datetime.now(timezone.utc)}
    if req.name           is not None: update["name"]           = req.name
    if req.city           is not None: update["city"]           = req.city
    if req.plan           is not None: update["plan"]           = req.plan
    if req.status         is not None: update["status"]         = req.status
    if req.members        is not None: update["members"]        = req.members
    if req.revenue        is not None: update["revenue"]        = req.revenue
    if req.price_per_user is not None: update["price_per_user"] = req.price_per_user
    col_gyms.update_one({"gym_id": gym_id}, {"$set": update})
    return {"status": "updated", "gym_id": gym_id}

# ══════════════════════════════════════════════════════════════════════════════
#  Gym deletion preview — returns counts before actual deletion
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/alpha/gyms/{gym_id}/delete-preview")
def gym_delete_preview(gym_id: str):
    """
    Returns counts of all data that will be deleted with this gym.
    Frontend calls this before showing the confirmation dialog.
    """
    gym = col_gyms.find_one({"gym_id": gym_id})
    if not gym:
        raise HTTPException(404, "Gym not found")

    member_count   = col_users.count_documents({"gym_id": gym_id})
    user_id_count  = col_user_ids.count_documents({"gym_id": gym_id})
    invoice_count  = col_invoices.count_documents({"gym_id": gym_id})
    banner_count   = col_banners.count_documents({"gym_id": gym_id})
    notif_count    = col_notifs.count_documents({"gym_id": gym_id})
    admin_count    = col_gym_admins.count_documents({"gym_id": gym_id})

    # Estimate meal records
    member_emails  = [u["email"] for u in col_users.find({"gym_id": gym_id}, {"email": 1})]
    meal_count     = col_meals.count_documents({"email": {"$in": member_emails}}) if member_emails else 0

    return {
        "gym_id":        gym_id,
        "gym_name":      gym.get("name", ""),
        "members":       member_count,
        "meals":         meal_count,
        "user_ids":      user_id_count,
        "invoices":      invoice_count,
        "banners":       banner_count,
        "notifications": notif_count,
        "admins":        admin_count,
    }

# ══════════════════════════════════════════════════════════════════════════════
#  Gym deletion — full cascade
# ══════════════════════════════════════════════════════════════════════════════

@app.delete("/alpha/gyms/{gym_id}")
def delete_gym(gym_id: str):
    """
    Permanently deletes the gym and ALL associated data:
    users, meals, scan limits, user IDs, invoices, banners,
    notifications, and gym admin accounts.
    """
    if not col_gyms.find_one({"gym_id": gym_id}):
        raise HTTPException(404, "Gym not found")

    summary = _cascade_delete_gym(gym_id)

    return {
        "status":  "deleted",
        "gym_id":  gym_id,
        "deleted": summary,
    }

# ══════════════════════════════════════════════════════════════════════════════
#  ROUTES — GYM ADMINS (alpha admin)
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/alpha/admins")
def list_gym_admins():
    docs = list(col_gym_admins.find().sort("created_at", DESCENDING))
    result = []
    for d in docs:
        d = _doc(d)
        d.pop("password", None)
        result.append(d)
    return result

@app.post("/alpha/admins/{gym_id}")
def create_gym_admin(gym_id: str, req: GymAdminUpdate):
    gym = col_gyms.find_one({"gym_id": gym_id})
    if not gym:
        raise HTTPException(404, "Gym not found")
    email = (req.email or "").strip().lower()
    if not email:
        raise HTTPException(400, "email is required")
    if col_gym_admins.find_one({"email": email}):
        raise HTTPException(409, "Admin email already exists")
    admin_id = "adm_" + str(uuid.uuid4())[:8]
    raw_pw   = re.sub(r"[^a-z0-9]", "", gym["name"].lower()) + "2025"
    hashed   = bcrypt.hashpw(raw_pw.encode(), bcrypt.gensalt()).decode()
    col_gym_admins.insert_one({
        "admin_id":   admin_id,
        "gym_id":     gym_id,
        "gym_name":   gym["name"],
        "name":       (req.name or "Admin").strip(),
        "email":      email,
        "password":   hashed,
        "status":     "active",
        "created_at": datetime.now(timezone.utc),
    })
    return {"status": "created", "admin_id": admin_id, "admin_email": email, "admin_password": raw_pw}

@app.patch("/alpha/admins/{admin_id}")
def update_gym_admin(admin_id: str, req: GymAdminUpdate):
    if not col_gym_admins.find_one({"admin_id": admin_id}):
        raise HTTPException(404, "Admin not found")
    update: dict = {"updated_at": datetime.now(timezone.utc)}
    if req.name   is not None: update["name"]   = req.name
    if req.email  is not None: update["email"]  = req.email.strip().lower()
    if req.status is not None: update["status"] = req.status
    col_gym_admins.update_one({"admin_id": admin_id}, {"$set": update})
    return {"status": "updated", "admin_id": admin_id}

@app.delete("/alpha/admins/{admin_id}")
def delete_gym_admin(admin_id: str):
    result = col_gym_admins.delete_one({"admin_id": admin_id})
    if result.deleted_count == 0:
        raise HTTPException(404, "Admin not found")
    return {"status": "deleted", "admin_id": admin_id}

# ══════════════════════════════════════════════════════════════════════════════
#  ROUTES — INVOICES (super admin — manual gym billing)
# ══════════════════════════════════════════════════════════════════════════════

@app.post("/alpha/invoices")
def create_invoice(req: InvoiceCreate):
    gym = col_gyms.find_one({"gym_id": req.gym_id})
    if not gym:
        raise HTTPException(404, "Gym not found")

    price_per_user = gym.get("price_per_user", 0.0)
    if price_per_user <= 0:
        raise HTTPException(400, "This gym has no price_per_user set. Update the gym first.")

    used_ids     = list(col_user_ids.find({"gym_id": req.gym_id, "status": "used"}))
    member_count = len(used_ids)

    if member_count == 0:
        raise HTTPException(400, "This gym has no active members yet (no used User IDs)")

    splits     = _calc_invoice_splits(price_per_user, member_count)
    invoice_id = str(uuid.uuid4())
    inv_number = _invoice_number()
    now        = datetime.now(timezone.utc)

    col_invoices.insert_one({
        "invoice_id":      invoice_id,
        "invoice_number":  inv_number,
        "gym_id":          req.gym_id,
        "gym_name":        gym["name"],
        "admin_email":     gym.get("admin_email", ""),
        "period":          req.period,
        "member_count":    member_count,
        "price_per_user":  price_per_user,
        "gross":           splits["gross"],
        "platform_amount": splits["platform_amount"],
        "gym_amount":      splits["gym_amount"],
        "platform_pct":    PLATFORM_SHARE_PCT,
        "gym_pct":         GYM_SHARE_PCT,
        "status":          "pending",
        "notes":           req.notes or "",
        "created_at":      now,
        "due_at":          now + timedelta(days=15),
        "paid_at":         None,
        "payment_ref":     None,
        "alerts":          [],
    })

    print(f"✅  Invoice {inv_number} created for {gym['name']} ({member_count} members) → ₹{splits['gross']}", flush=True)
    return {
        "status":         "created",
        "invoice_id":     invoice_id,
        "invoice_number": inv_number,
        "member_count":   member_count,
        **splits,
        "due_at":         (now + timedelta(days=15)).isoformat(),
    }

@app.get("/alpha/invoices")
def list_all_invoices(status: str = None):
    query = {}
    if status:
        query["status"] = status
    docs = list(col_invoices.find(query).sort("created_at", DESCENDING))
    return [_doc(d) for d in docs]

@app.get("/alpha/invoices/{invoice_id}")
def get_invoice(invoice_id: str):
    inv = col_invoices.find_one({"invoice_id": invoice_id})
    if not inv:
        raise HTTPException(404, "Invoice not found")
    return _doc(inv)

@app.patch("/alpha/invoices/{invoice_id}/status")
def update_invoice_status(invoice_id: str, req: InvoiceStatusUpdate):
    inv = col_invoices.find_one({"invoice_id": invoice_id})
    if not inv:
        raise HTTPException(404, "Invoice not found")

    update: dict = {"status": req.status, "updated_at": datetime.now(timezone.utc)}
    if req.paid_at:     update["paid_at"]     = req.paid_at
    if req.payment_ref: update["payment_ref"] = req.payment_ref

    if req.status == "paid":
        col_gyms.update_one(
            {"gym_id": inv["gym_id"]},
            {"$inc": {"revenue": inv.get("gym_amount", 0)}}
        )

    col_invoices.update_one({"invoice_id": invoice_id}, {"$set": update})
    print(f"✅  Invoice {inv['invoice_number']} → {req.status}", flush=True)
    return {"status": "updated", "invoice_id": invoice_id, "new_status": req.status}

@app.delete("/alpha/invoices/{invoice_id}")
def delete_invoice(invoice_id: str):
    result = col_invoices.delete_one({"invoice_id": invoice_id})
    if result.deleted_count == 0:
        raise HTTPException(404, "Invoice not found")
    return {"status": "deleted"}

@app.post("/alpha/invoices/{invoice_id}/alert")
def send_invoice_alert(invoice_id: str, req: InvoiceAlert):
    inv = col_invoices.find_one({"invoice_id": invoice_id})
    if not inv:
        raise HTTPException(404, "Invoice not found")

    now       = datetime.now(timezone.utc)
    alert_doc = {
        "alert_id": str(uuid.uuid4()),
        "type":     req.alert_type,
        "message":  req.message,
        "sent_at":  now,
    }

    col_invoices.update_one({"invoice_id": invoice_id}, {"$push": {"alerts": alert_doc}})
    col_notifs.insert_one({
        "notification_id": str(uuid.uuid4()),
        "gym_id":          inv["gym_id"],
        "title":           _alert_title(req.alert_type, inv["invoice_number"]),
        "body":            req.message,
        "type":            "billing",
        "segments":        ["admin"],
        "deep_link":       f"aerofit://billing/invoice/{invoice_id}",
        "scheduled_at":    "",
        "sent_at":         now,
        "invoice_id":      invoice_id,
    })

    print(f"✅  Alert sent for invoice {inv['invoice_number']} → {req.alert_type}", flush=True)
    return {"status": "sent", "alert_id": alert_doc["alert_id"]}

def _alert_title(alert_type: str, inv_number: str) -> str:
    MAP = {
        "payment_reminder": f"💳 Payment Due — {inv_number}",
        "overdue":          f"🚨 Overdue Invoice — {inv_number}",
        "receipt":          f"✅ Payment Received — {inv_number}",
    }
    return MAP.get(alert_type, f"📋 Invoice Alert — {inv_number}")

# ══════════════════════════════════════════════════════════════════════════════
#  ROUTES — INVOICES (gym admin view)
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/gym/{gym_id}/invoices")
def list_gym_invoices(gym_id: str):
    if not col_gyms.find_one({"gym_id": gym_id}):
        raise HTTPException(404, "Gym not found")
    docs = list(col_invoices.find({"gym_id": gym_id}).sort("created_at", DESCENDING))
    return [_doc(d) for d in docs]

@app.get("/gym/{gym_id}/billing-summary")
def gym_billing_summary(gym_id: str):
    gym = col_gyms.find_one({"gym_id": gym_id})
    if not gym:
        raise HTTPException(404, "Gym not found")

    invoices = list(col_invoices.find({"gym_id": gym_id}))
    paid     = [i for i in invoices if i.get("status") == "paid"]
    pending  = [i for i in invoices if i.get("status") == "pending"]
    overdue  = [i for i in invoices if i.get("status") == "overdue"]

    return {
        "price_per_user":    gym.get("price_per_user", 0),
        "platform_pct":      PLATFORM_SHARE_PCT,
        "gym_pct":           GYM_SHARE_PCT,
        "total_invoices":    len(invoices),
        "total_paid":        sum(i.get("gross", 0) for i in paid),
        "total_pending":     sum(i.get("gross", 0) for i in pending),
        "total_overdue":     sum(i.get("gross", 0) for i in overdue),
        "gym_earnings":      sum(i.get("gym_amount", 0) for i in paid),
        "platform_earnings": sum(i.get("platform_amount", 0) for i in paid),
        "paid_count":        len(paid),
        "pending_count":     len(pending),
        "overdue_count":     len(overdue),
    }

# ══════════════════════════════════════════════════════════════════════════════
#  ROUTES — USER IDs
# ══════════════════════════════════════════════════════════════════════════════

@app.post("/gym/{gym_id}/user-ids/generate")
def generate_user_ids(gym_id: str, req: GenerateUserIdsRequest):
    if not col_gyms.find_one({"gym_id": gym_id}):
        raise HTTPException(404, "Gym not found")

    count       = max(1, req.count)
    plan_months = max(1, min(req.plan_months, 12))
    plan_label  = f"{plan_months} Month{'s' if plan_months > 1 else ''}"
    codes       = []
    now         = datetime.now(timezone.utc)

    for _ in range(count):
        for _attempt in range(10):
            code = _generate_code()
            if not col_user_ids.find_one({"code": code}):
                break
        col_user_ids.insert_one({
            "gym_id":      gym_id,
            "code":        code,
            "status":      "active",
            "plan_months": plan_months,
            "plan_label":  plan_label,
            "created_at":  now,
            "used_at":     None,
            "used_by":     None,
            "expires_at":  None,
        })
        codes.append(code)

    print(f"✅  Generated {count} User ID(s) for {gym_id} — plan: {plan_label}", flush=True)
    return {
        "status":      "created",
        "gym_id":      gym_id,
        "codes":       codes,
        "plan_months": plan_months,
        "plan_label":  plan_label,
    }

@app.get("/gym/{gym_id}/user-ids")
def list_user_ids(gym_id: str):
    if not col_gyms.find_one({"gym_id": gym_id}):
        raise HTTPException(404, "Gym not found")
    docs = list(col_user_ids.find({"gym_id": gym_id}).sort("created_at", DESCENDING))
    return [_doc(d) for d in docs]

@app.post("/gym/{gym_id}/validate-user-id")
def validate_user_id(gym_id: str, req: ValidateUserIdRequest):
    code = req.user_id.strip().upper()
    doc  = col_user_ids.find_one({"gym_id": gym_id, "code": code})
    if not doc:
        return {"valid": False, "reason": "Code not found for this gym"}
    if doc.get("status") != "active":
        return {"valid": False, "reason": "Code has already been used"}
    return {
        "valid":       True,
        "plan_months": doc.get("plan_months", 1),
        "plan_label":  doc.get("plan_label", "1 Month"),
    }

@app.delete("/gym/{gym_id}/user-ids/{code}")
def revoke_user_id(gym_id: str, code: str):
    code   = code.strip().upper()
    result = col_user_ids.delete_one({"gym_id": gym_id, "code": code, "status": "active"})
    if result.deleted_count == 0:
        raise HTTPException(404, "Active code not found")
    return {"status": "revoked", "code": code}

@app.patch("/gym/{gym_id}/user-ids/{code}/plan")
def update_user_id_plan(gym_id: str, code: str, req: UpdateUserIdPlan):
    code = code.strip().upper()
    doc  = col_user_ids.find_one({"gym_id": gym_id, "code": code})
    if not doc:
        raise HTTPException(404, "User ID not found")
    if doc.get("status") != "active":
        raise HTTPException(400, "Cannot change plan on a used User ID")
    plan_months = max(1, min(req.plan_months, 12))
    plan_label  = f"{plan_months} Month{'s' if plan_months > 1 else ''}"
    col_user_ids.update_one(
        {"gym_id": gym_id, "code": code},
        {"$set": {"plan_months": plan_months, "plan_label": plan_label}}
    )
    print(f"✅  Plan updated → {code}  {plan_label}", flush=True)
    return {"status": "updated", "code": code, "plan_months": plan_months, "plan_label": plan_label}

# ══════════════════════════════════════════════════════════════════════════════
#  ROUTES — USER MANAGEMENT (gym members — no payment needed)
# ══════════════════════════════════════════════════════════════════════════════

@app.post("/admin/add-user")
def add_user(req: AddUserRequest):
    email = req.email.strip().lower()
    if not re.match(r"^[\w\.-]+@[\w\.-]+\.\w{2,}$", email):
        raise HTTPException(400, "Invalid email address")
    if col_users.find_one({"email": email}):
        raise HTTPException(409, "User already exists")

    plan_months = 1
    plan_label  = "1 Month"

    if req.gym_id and req.user_id:
        gym_id = req.gym_id.strip()
        code   = req.user_id.strip().upper()
        doc    = col_user_ids.find_one({"gym_id": gym_id, "code": code})
        if not doc:
            raise HTTPException(400, "Invalid User ID for this gym")
        if doc.get("status") != "active":
            raise HTTPException(400, "This User ID has already been used")

        plan_months = doc.get("plan_months", 1)
        plan_label  = doc.get("plan_label", f"{plan_months} Month{'s' if plan_months > 1 else ''}")
        used_at     = datetime.now(timezone.utc)
        expires_at  = used_at + timedelta(days=30 * plan_months)

        col_user_ids.update_one(
            {"gym_id": gym_id, "code": code, "status": "active"},
            {"$set": {
                "status":     "used",
                "used_at":    used_at,
                "used_by":    email,
                "expires_at": expires_at,
            }},
        )
        col_gyms.update_one({"gym_id": gym_id}, {"$inc": {"members": 1}})

    hashed = bcrypt.hashpw(req.password.encode(), bcrypt.gensalt()).decode()
    col_users.insert_one({
        "email":              email,
        "name":               req.name.strip(),
        "password":           hashed,
        "weight_kg":          req.weight_kg,
        "height_cm":          req.height_cm,
        "gym_id":             req.gym_id or None,
        "plan_months":        plan_months,
        "plan_label":         plan_label,
        "indie_plan":         False,
        "membership_expired": False,
        "created_at":         datetime.now(timezone.utc),
    })
    return {"status": "created", "email": email, "plan_months": plan_months, "plan_label": plan_label}

@app.get("/admin/users")
def list_users():
    docs = list(col_users.find().sort("created_at", DESCENDING))
    return [
        {
            "email":              d["email"],
            "name":               d["name"],
            "weight_kg":          d["weight_kg"],
            "height_cm":          d["height_cm"],
            "gym_id":             d.get("gym_id"),
            "indie_plan":         d.get("indie_plan", False),
            "plan_months":        d.get("plan_months", 1),
            "plan_label":         d.get("plan_label", "1 Month"),
            "membership_expired": d.get("membership_expired", False),
            "created_at":         _fmt_dt(d.get("created_at")),
        }
        for d in docs
    ]

@app.delete("/admin/users/{email}")
def remove_user(email: str):
    result = col_users.delete_one({"email": email.lower()})
    if result.deleted_count == 0:
        raise HTTPException(404, "User not found")
    return {"status": "deleted"}

# ══════════════════════════════════════════════════════════════════════════════
#  ROUTES — USER AUTH
# ══════════════════════════════════════════════════════════════════════════════

@app.post("/user/login")
def user_login(req: UserLogin):
    email = req.email.strip().lower()
    user  = col_users.find_one({"email": email})
    if not user or not user.get("password"):
        raise HTTPException(401, "Invalid email or password")
    if not bcrypt.checkpw(req.password.encode(), user["password"].encode()):
        raise HTTPException(401, "Invalid email or password")

    if user.get("membership_expired"):
        raise HTTPException(403, "membership_expired")

    now = datetime.now(timezone.utc)

    if user.get("indie_plan") and user.get("indie_expires_at"):
        indie_exp = _ensure_utc(user["indie_expires_at"])
        if indie_exp and indie_exp <= now:
            col_users.update_one(
                {"email": email},
                {"$set": {
                    "membership_expired":    True,
                    "membership_expired_at": now,
                }}
            )
            raise HTTPException(403, "membership_expired")

    gym_name = ""
    if user.get("gym_id"):
        gym = col_gyms.find_one({"gym_id": user["gym_id"]})
        if gym:
            gym_name = gym.get("name", "")

    membership_expires = None

    if user.get("gym_id"):
        uid_doc = col_user_ids.find_one({"used_by": email, "gym_id": user["gym_id"]})
        if uid_doc and uid_doc.get("expires_at"):
            if _ensure_utc(uid_doc["expires_at"]) <= now:
                col_users.update_one(
                    {"email": email},
                    {"$set": {
                        "membership_expired":    True,
                        "membership_expired_at": now,
                        "gym_id":                None,
                    }}
                )
                raise HTTPException(403, "membership_expired")
            membership_expires = _fmt_dt(uid_doc["expires_at"])

    if user.get("indie_plan") and user.get("indie_expires_at") and not membership_expires:
        membership_expires = _fmt_dt(user["indie_expires_at"])

    return {
        "status": "ok",
        "user": {
            "email":              user["email"],
            "name":               user["name"],
            "weight_kg":          user["weight_kg"],
            "height_cm":          user["height_cm"],
            "gym_id":             user.get("gym_id"),
            "gym_name":           gym_name,
            "indie_plan":         user.get("indie_plan", False),
            "plan_months":        user.get("plan_months", 1),
            "plan_label":         user.get("plan_label", "1 Month"),
            "membership_expired": False,
            "membership_expires": membership_expires,
        },
    }

@app.get("/user/{email}")
def get_user(email: str):
    user = col_users.find_one({"email": email.lower()})
    if not user:
        raise HTTPException(404, "User not found")

    gym_name = ""
    if user.get("gym_id"):
        gym = col_gyms.find_one({"gym_id": user["gym_id"]})
        if gym:
            gym_name = gym.get("name", "")

    membership_expires = None

    if user.get("gym_id"):
        uid_doc = col_user_ids.find_one({"used_by": email.lower(), "gym_id": user["gym_id"]})
        if uid_doc and uid_doc.get("expires_at"):
            membership_expires = _fmt_dt(uid_doc["expires_at"])

    if user.get("indie_plan") and user.get("indie_expires_at") and not membership_expires:
        membership_expires = _fmt_dt(user["indie_expires_at"])

    return {
        "email":              user["email"],
        "name":               user["name"],
        "weight_kg":          user["weight_kg"],
        "height_cm":          user["height_cm"],
        "gym_id":             user.get("gym_id"),
        "gym_name":           gym_name,
        "indie_plan":         user.get("indie_plan", False),
        "plan_months":        user.get("plan_months", 1),
        "plan_label":         user.get("plan_label", "1 Month"),
        "membership_expired": user.get("membership_expired", False),
        "membership_expires": membership_expires,
    }

@app.put("/user/{email}")
def update_user(email: str, req: UserUpdate):
    email = email.lower()
    if not col_users.find_one({"email": email}):
        raise HTTPException(404, "User not found")
    update: dict = {"updated_at": datetime.now(timezone.utc)}
    if req.name      is not None: update["name"]      = req.name
    if req.weight_kg is not None: update["weight_kg"] = req.weight_kg
    if req.height_cm is not None: update["height_cm"] = req.height_cm
    col_users.update_one({"email": email}, {"$set": update})
    return {"status": "updated"}

# ══════════════════════════════════════════════════════════════════════════════
#  ROUTES — FCM TOKEN
# ══════════════════════════════════════════════════════════════════════════════

@app.post("/user/{email}/fcm-token")
def update_fcm_token(email: str, req: FcmTokenUpdate):
    col_users.update_one(
        {"email": email.lower()},
        {"$set": {
            "fcm_token":  req.fcm_token,
            "updated_at": datetime.now(timezone.utc),
        }}
    )
    return {"status": "ok"}

# ══════════════════════════════════════════════════════════════════════════════
#  ROUTES — MEMBERSHIP STATUS
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/user/{email}/membership-status")
def membership_status(email: str):
    email = email.strip().lower()
    user  = col_users.find_one({"email": email})
    if not user:
        raise HTTPException(404, "User not found")

    if user.get("membership_expired"):
        return {
            "valid":      False,
            "reason":     "expired",
            "expired_at": _fmt_dt(user.get("membership_expired_at")),
        }

    now = datetime.now(timezone.utc)

    if user.get("indie_plan") and user.get("indie_expires_at"):
        indie_exp = _ensure_utc(user["indie_expires_at"])
        if indie_exp and indie_exp <= now:
            col_users.update_one(
                {"email": email},
                {"$set": {
                    "membership_expired":    True,
                    "membership_expired_at": now,
                }}
            )
            return {
                "valid":      False,
                "reason":     "expired",
                "expired_at": _fmt_dt(indie_exp),
            }
        return {
            "valid":      True,
            "reason":     "active",
            "expires_at": _fmt_dt(indie_exp),
        }

    if not user.get("gym_id"):
        return {"valid": True, "reason": "no_gym"}

    uid_doc = col_user_ids.find_one({"used_by": email, "gym_id": user["gym_id"]})

    if uid_doc:
        expires_at = uid_doc.get("expires_at")
        if expires_at and _ensure_utc(expires_at) <= now:
            col_users.update_one(
                {"email": email},
                {"$set": {
                    "membership_expired":    True,
                    "membership_expired_at": now,
                    "gym_id":                None,
                }}
            )
            return {
                "valid":      False,
                "reason":     "expired",
                "expired_at": _fmt_dt(expires_at),
            }
        return {
            "valid":      True,
            "reason":     "active",
            "expires_at": _fmt_dt(expires_at),
        }

    return {"valid": True, "reason": "active"}

# ══════════════════════════════════════════════════════════════════════════════
#  ROUTES — BANNERS
# ══════════════════════════════════════════════════════════════════════════════

@app.post("/gym/{gym_id}/banners")
def create_banner(gym_id: str, req: BannerCreate):
    if not col_gyms.find_one({"gym_id": gym_id}):
        raise HTTPException(404, "Gym not found")
    if req.gym_id != gym_id:
        raise HTTPException(403, "Cannot create banners for a different gym")
    banner_id = str(uuid.uuid4())
    image_url = upload_image(req.image_base64 or "", folder="aerofitdb/banners", public_id=banner_id)
    doc = {
        "banner_id":  banner_id,
        "gym_id":     gym_id,
        "title":      req.title,
        "screen":     req.screen,
        "status":     req.status,
        "expires_at": req.expires_at or "",
        "deep_link":  req.deep_link  or "",
        "image_url":  image_url,
        "created_at": datetime.now(timezone.utc),
    }
    col_banners.insert_one(doc)
    return {"status": "created", "banner_id": banner_id, "image_url": image_url}

@app.get("/gym/{gym_id}/banners")
def list_banners(gym_id: str, screen: str = None):
    if not col_gyms.find_one({"gym_id": gym_id}):
        raise HTTPException(404, "Gym not found")
    query = {"gym_id": gym_id}
    if screen:
        query["screen"] = screen
    docs = list(col_banners.find(query).sort("created_at", DESCENDING))
    return [_doc(d) for d in docs]

@app.delete("/gym/{gym_id}/banners/{banner_id}")
def delete_banner(gym_id: str, banner_id: str):
    if not col_gyms.find_one({"gym_id": gym_id}):
        raise HTTPException(404, "Gym not found")
    banner = col_banners.find_one({"banner_id": banner_id, "gym_id": gym_id})
    if not banner:
        raise HTTPException(404, "Banner not found or belongs to a different gym")
    image_url = banner.get("image_url", "")
    if image_url:
        try:
            cloudinary.uploader.destroy(f"aerofitdb/banners/{banner_id}", resource_type="image")
            print(f"✅  Cloudinary image deleted → aerofitdb/banners/{banner_id}", flush=True)
        except Exception as e:
            print(f"⚠️  Cloudinary delete failed: {e}", flush=True)
    col_banners.delete_one({"banner_id": banner_id, "gym_id": gym_id})
    return {"status": "deleted"}

# ══════════════════════════════════════════════════════════════════════════════
#  ROUTES — NOTIFICATIONS (with FCM push)
# ══════════════════════════════════════════════════════════════════════════════

@app.post("/gym/{gym_id}/notifications")
def create_notification(gym_id: str, req: NotificationCreate):
    if not col_gyms.find_one({"gym_id": gym_id}):
        raise HTTPException(404, "Gym not found")
    if req.gym_id != gym_id:
        raise HTTPException(403, "Cannot create notifications for a different gym")

    notif_id = str(uuid.uuid4())
    col_notifs.insert_one({
        "notification_id": notif_id,
        "gym_id":          gym_id,
        "title":           req.title,
        "body":            req.body,
        "type":            req.type,
        "segments":        req.segments,
        "deep_link":       req.deep_link    or "",
        "scheduled_at":    req.scheduled_at or "",
        "sent_at":         datetime.now(timezone.utc),
    })

    # ── Fire FCM push in background — API responds instantly ─────────────────
    threading.Thread(
        target=_send_fcm_push,
        args=(gym_id, req.title, req.body),
        kwargs={"data": {
            "type":     req.type,
            "gym_id":   gym_id,
            "notif_id": notif_id,
        }},
        daemon=True,
    ).start()

    return {"status": "sent", "notification_id": notif_id}

@app.get("/gym/{gym_id}/notifications")
def list_notifications(gym_id: str):
    if not col_gyms.find_one({"gym_id": gym_id}):
        raise HTTPException(404, "Gym not found")
    docs = list(col_notifs.find({"gym_id": gym_id}).sort("sent_at", DESCENDING).limit(50))
    return [_doc(d) for d in docs]

@app.delete("/gym/{gym_id}/notifications/{notification_id}")
def delete_notification(gym_id: str, notification_id: str):
    if not col_gyms.find_one({"gym_id": gym_id}):
        raise HTTPException(404, "Gym not found")
    result = col_notifs.delete_one({"notification_id": notification_id, "gym_id": gym_id})
    if result.deleted_count == 0:
        raise HTTPException(404, "Notification not found or belongs to a different gym")
    return {"status": "deleted"}

# ══════════════════════════════════════════════════════════════════════════════
#  ROUTES — SCAN LIMIT
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/scan-limit/{email}")
def get_scan_limit(email: str):
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    doc   = col_scan_limits.find_one({"email": email.lower(), "date": today})
    used  = doc.get("count", 0) if doc else 0
    return {
        "email":     email.lower(),
        "used":      used,
        "limit":     SCAN_LIMIT,
        "remaining": max(0, SCAN_LIMIT - used),
    }

# ══════════════════════════════════════════════════════════════════════════════
#  ROUTES — MEALS
# ══════════════════════════════════════════════════════════════════════════════

@app.post("/analyze-meal")
async def analyze_meal(req: MealRequest):
    email = req.email.strip().lower() if req.email else ""

    user_lock = await _get_user_lock(email) if email else None

    if user_lock and user_lock.locked():
        return JSONResponse(
            status_code=409,
            content={"detail": "A scan is already in progress for your account. Please wait."},
        )

    async def _run_analysis():
        if _gemini_semaphore._value == 0:
            return JSONResponse(
                status_code=503,
                content={"detail": "Server is busy. Please try again shortly."},
                headers={"Retry-After": "10"},
            )

        try:
            async with _gemini_semaphore:
                remaining = 0
                if email:
                    try:
                        remaining = _check_and_increment_scan_limit(email)
                    except HTTPException as e:
                        if e.status_code == 429:
                            return JSONResponse(
                                status_code=429,
                                content={"detail": e.detail},
                            )
                        raise

                image_part = _b64_to_part(req.image_base64)
                prompt = (
                    "Estimate nutrition for the EXACT portion shown. Return ONLY JSON:\n"
                    '{"name":"","serving_size":"","kcal":0,"protein":0,"carbs":0,"fat":0,"fiber":0,"notes":""}'
                )
                loop = asyncio.get_running_loop()
                text = await loop.run_in_executor(
                    None,
                    lambda: _ask_gemini([image_part], prompt),
                )

                d      = _extract_json(text)
                result = {
                    "name":            str(d.get("name",         "Meal")),
                    "serving_size":    str(d.get("serving_size", "1 serving")),
                    "kcal":            _safe_int(d.get("kcal")),
                    "protein":         _safe_int(d.get("protein")),
                    "carbs":           _safe_int(d.get("carbs")),
                    "fat":             _safe_int(d.get("fat")),
                    "fiber":           _safe_int(d.get("fiber")),
                    "notes":           str(d.get("notes", "")),
                    "scans_remaining": remaining,
                }

                print(
                    f"✅  Scan → {email or 'anon'}  {result['name']}  {result['kcal']} kcal  "
                    f"[{MAX_CONCURRENT_SCANS - _gemini_semaphore._value}/{MAX_CONCURRENT_SCANS} slots]",
                    flush=True,
                )
                return result

        except HTTPException:
            raise
        except Exception as e:
            traceback.print_exc()
            raise HTTPException(500, f"Analysis failed: {str(e)}")

    if user_lock:
        async with user_lock:
            result = await _run_analysis()
    else:
        result = await _run_analysis()

    if hash(email) % 100 == 0:
        asyncio.create_task(_cleanup_stale_locks())

    return result


@app.post("/log-meal")
def log_meal(req: LogMealRequest):
    try:
        meal_id   = str(uuid.uuid4())
        image_url = upload_image(
            req.image_base64 or "",
            folder    = f"aerofitdb/meals/{req.email.lower()}",
            public_id = meal_id,
        )
        col_meals.insert_one({
            "meal_id":      meal_id,
            "email":        req.email.lower(),
            "name":         req.name,
            "kcal":         req.kcal,
            "protein":      req.protein,
            "carbs":        req.carbs,
            "fat":          req.fat,
            "fiber":        req.fiber,
            "serving_size": req.serving_size,
            "image_url":    image_url,
            "logged_at":    datetime.now(timezone.utc),
        })
        return {"status": "logged", "meal_id": meal_id, "image_url": image_url}
    except HTTPException:
        raise
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(500, f"Meal log failed: {str(e)}")

@app.get("/meals/{email}")
def get_meals(email: str, days: int = 1):
    since = datetime.now(timezone.utc) - timedelta(days=days)
    docs  = list(
        col_meals.find({"email": email.lower(), "logged_at": {"$gte": since}})
        .sort("logged_at", DESCENDING)
    )
    return [_doc(d) for d in docs]

@app.delete("/meal/{meal_id}")
def delete_meal(meal_id: str):
    result = col_meals.delete_one({"meal_id": meal_id})
    if result.deleted_count == 0:
        raise HTTPException(404, "Meal not found")
    return {"status": "deleted"}

# ══════════════════════════════════════════════════════════════════════════════
#  ROUTES — INDIE PLAN (Razorpay — independent users only)
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/indie/pricing/{months}")
def indie_pricing(months: int):
    if months < 1 or months > 12:
        raise HTTPException(400, "months must be 1–12")
    return _indie_pricing(months)


@app.post("/indie/create-order")
def indie_create_order(req: IndieOrderRequest):
    email = req.email.strip().lower()
    if not re.match(r"^[\w\.-]+@[\w\.-]+\.\w{2,}$", email):
        raise HTTPException(400, "Invalid email address")
    if col_users.find_one({"email": email}):
        raise HTTPException(409, "An account with this email already exists")

    existing_pending = col_payments.find_one({"email": email, "status": "pending"})
    if existing_pending:
        pricing = _indie_pricing(existing_pending["months"])
        return {
            "order_id":        existing_pending["order_id"],
            "key_id":          RAZORPAY_KEY_ID,
            "amount":          existing_pending["amount_paise"],
            "currency":        "INR",
            "name":            "AERO-FIT",
            "description":     f"{existing_pending['months']} Month — Independent Plan",
            "prefill_email":   email,
            "prefill_name":    existing_pending["name"],
            **pricing,
        }

    months  = max(1, min(req.months, 12))
    pricing = _indie_pricing(months)
    now     = datetime.now(timezone.utc)

    try:
        rp_order = razorpay_client.order.create({
            "amount":   pricing["final_paise"],
            "currency": "INR",
            "receipt":  f"af_{email[:12]}_{now.strftime('%m%d%H%M%S')}",
            "notes":    {"email": email, "months": str(months), "app": "aerofit"},
        })
    except Exception as e:
        print(f"❌  Razorpay order creation failed: {e}", flush=True)
        raise HTTPException(502, "Payment gateway error. Please try again.")

    order_id  = rp_order["id"]
    hashed_pw = bcrypt.hashpw(req.password.encode(), bcrypt.gensalt()).decode()

    col_payments.insert_one({
        "order_id":     order_id,
        "payment_id":   None,
        "email":        email,
        "name":         req.name.strip(),
        "password":     hashed_pw,
        "weight_kg":    req.weight_kg,
        "height_cm":    req.height_cm,
        "months":       months,
        "amount_inr":   pricing["final_inr"],
        "amount_paise": pricing["final_paise"],
        "discount_pct": pricing["discount_pct"],
        "status":       "pending",
        "type":         "new",
        "created_at":   now,
        "verified_at":  None,
    })

    print(f"✅  Indie order created → {order_id}  {email}  {months}mo  ₹{pricing['final_inr']}", flush=True)
    return {
        "order_id":      order_id,
        "key_id":        RAZORPAY_KEY_ID,
        "amount":        pricing["final_paise"],
        "currency":      "INR",
        "name":          "AERO-FIT",
        "description":   f"{months} Month{'s' if months > 1 else ''} — Independent Plan",
        "prefill_email": email,
        "prefill_name":  req.name.strip(),
        **pricing,
    }


@app.post("/indie/verify-payment")
def indie_verify_payment(req: IndieVerifyRequest):
    if not _verify_hmac(req.razorpay_order_id, req.razorpay_payment_id, req.razorpay_signature):
        raise HTTPException(400, "Payment verification failed. Signature mismatch.")

    pending = col_payments.find_one({
        "order_id": req.razorpay_order_id,
        "status":   "pending",
        "type":     "new",
    })
    if not pending:
        raise HTTPException(404, "Order not found or already processed")

    email  = pending["email"]
    months = pending["months"]
    now    = datetime.now(timezone.utc)

    if col_users.find_one({"email": email}):
        raise HTTPException(409, "Account already exists for this email")

    expires_at = now + timedelta(days=30 * months)

    col_users.insert_one({
        "email":              email,
        "name":               pending["name"],
        "password":           pending["password"],
        "weight_kg":          pending["weight_kg"],
        "height_cm":          pending["height_cm"],
        "gym_id":             None,
        "plan_months":        months,
        "plan_label":         f"{months} Month{'s' if months > 1 else ''}",
        "indie_plan":         True,
        "indie_expires_at":   expires_at,
        "membership_expired": False,
        "created_at":         now,
    })

    col_payments.update_one(
        {"order_id": req.razorpay_order_id},
        {"$set": {
            "payment_id":  req.razorpay_payment_id,
            "status":      "paid",
            "verified_at": now,
        }},
    )

    print(f"✅  Indie payment verified → {email}  {months}mo  ₹{pending['amount_inr']}  pid={req.razorpay_payment_id}", flush=True)
    return {
        "status": "ok",
        "user": {
            "email":              email,
            "name":               pending["name"],
            "weight_kg":          pending["weight_kg"],
            "height_cm":          pending["height_cm"],
            "gym_id":             None,
            "gym_name":           "",
            "indie_plan":         True,
            "plan_months":        months,
            "plan_label":         f"{months} Month{'s' if months > 1 else ''}",
            "indie_expires_at":   expires_at.isoformat(),
            "membership_expired": False,
            "membership_expires": expires_at.isoformat(),
        },
    }


@app.post("/indie/create-renewal-order")
def indie_create_renewal_order(req: IndieRenewOrderRequest):
    email = req.email.strip().lower()
    user  = col_users.find_one({"email": email})
    if not user:
        raise HTTPException(404, "User not found")
    if not user.get("indie_plan"):
        raise HTTPException(400, "Only independent plan users can renew here")
    if not bcrypt.checkpw(req.password.encode(), user["password"].encode()):
        raise HTTPException(401, "Invalid password")

    months  = max(1, min(req.months, 12))
    pricing = _indie_pricing(months)
    now     = datetime.now(timezone.utc)

    try:
        rp_order = razorpay_client.order.create({
            "amount":   pricing["final_paise"],
            "currency": "INR",
            "receipt":  f"rn_{email[:12]}_{now.strftime('%m%d%H%M%S')}",
            "notes":    {"email": email, "months": str(months), "type": "renewal"},
        })
    except Exception as e:
        print(f"❌  Razorpay renewal order creation failed: {e}", flush=True)
        raise HTTPException(502, "Payment gateway error. Please try again.")

    order_id = rp_order["id"]

    col_payments.insert_one({
        "order_id":     order_id,
        "payment_id":   None,
        "email":        email,
        "name":         user["name"],
        "password":     None,
        "weight_kg":    user["weight_kg"],
        "height_cm":    user["height_cm"],
        "months":       months,
        "amount_inr":   pricing["final_inr"],
        "amount_paise": pricing["final_paise"],
        "discount_pct": pricing["discount_pct"],
        "status":       "pending",
        "type":         "renewal",
        "created_at":   now,
        "verified_at":  None,
    })

    print(f"✅  Renewal order created → {order_id}  {email}  {months}mo  ₹{pricing['final_inr']}", flush=True)
    return {
        "order_id":      order_id,
        "key_id":        RAZORPAY_KEY_ID,
        "amount":        pricing["final_paise"],
        "currency":      "INR",
        "name":          "AERO-FIT",
        "description":   f"Renewal — {months} Month{'s' if months > 1 else ''}",
        "prefill_email": email,
        "prefill_name":  user["name"],
        **pricing,
    }


@app.post("/indie/verify-renewal")
def indie_verify_renewal(req: IndieVerifyRequest):
    if not _verify_hmac(req.razorpay_order_id, req.razorpay_payment_id, req.razorpay_signature):
        raise HTTPException(400, "Payment verification failed. Signature mismatch.")

    pending = col_payments.find_one({
        "order_id": req.razorpay_order_id,
        "status":   "pending",
        "type":     "renewal",
    })
    if not pending:
        raise HTTPException(404, "Renewal order not found or already processed")

    email  = pending["email"]
    months = pending["months"]
    now    = datetime.now(timezone.utc)

    user = col_users.find_one({"email": email})
    if not user:
        raise HTTPException(404, "User not found")

    current_exp = _ensure_utc(user.get("indie_expires_at"))
    base        = current_exp if (current_exp and current_exp > now) else now
    new_exp     = base + timedelta(days=30 * months)

    col_users.update_one(
        {"email": email},
        {"$set": {
            "indie_expires_at":   new_exp,
            "membership_expired": False,
            "plan_months":        months,
            "plan_label":         f"{months} Month{'s' if months > 1 else ''}",
        }}
    )

    col_payments.update_one(
        {"order_id": req.razorpay_order_id},
        {"$set": {
            "payment_id":  req.razorpay_payment_id,
            "status":      "paid",
            "verified_at": now,
        }},
    )

    print(f"✅  Renewal verified → {email}  {months}mo  new expiry: {new_exp.isoformat()}  pid={req.razorpay_payment_id}", flush=True)
    return {
        "status":             "renewed",
        "email":              email,
        "months":             months,
        "new_expires_at":     new_exp.isoformat(),
        "membership_expires": new_exp.isoformat(),
    }


@app.get("/indie/payment-status/{order_id}")
def indie_payment_status(order_id: str):
    doc = col_payments.find_one({"order_id": order_id})
    if not doc:
        raise HTTPException(404, "Order not found")
    return {
        "order_id":   order_id,
        "status":     doc.get("status"),
        "type":       doc.get("type", "new"),
        "email":      doc.get("email"),
        "months":     doc.get("months"),
        "amount_inr": doc.get("amount_inr"),
    }

# ══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))