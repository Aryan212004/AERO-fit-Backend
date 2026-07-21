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
import random
import resend
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

# ── Pro plan admin-dashboard activation fee (super-admin created Pro gyms) ───
# Charged once at first gym-admin login, then annually thereafter. Gates the
# ENTIRE admin dashboard (banners, notifications, User IDs, everything) until
# paid — see /gym/{gym_id}/pro-activation-status and friends below.
# Live value: ₹5000/year. Can still be overridden via the PRO_ACTIVATION_FEE_INR
# env var if you ever need to change it without a redeploy.
PRO_ACTIVATION_FEE_INR = float(os.environ.get("PRO_ACTIVATION_FEE_INR", "5000"))  # ₹/year

INDIE_BASE_PRICE   = float(os.environ.get("INDIE_BASE_PRICE",  "159"))  # ₹/month — Android/Razorpay
INDIE_DISCOUNT_PCT = float(os.environ.get("INDIE_DISCOUNT_PCT", "1"))   # 1% per extra month — Android/Razorpay

# ── iOS / Apple In-App Purchase pricing ──────────────────────────────────────
IOS_INDIE_BASE_PRICE = float(os.environ.get("IOS_INDIE_BASE_PRICE", "199"))  # ₹/month — Apple IAP only

APPLE_SHARED_SECRET     = os.environ.get("APPLE_SHARED_SECRET", "").strip()
if APPLE_SHARED_SECRET:
    print(f"✅  Apple shared secret configured → {APPLE_SHARED_SECRET[:6]}…", flush=True)
else:
    print("⚠️  APPLE_SHARED_SECRET not set — Apple IAP purchases will fail verification", flush=True)
APPLE_VERIFY_URL_PROD    = "https://buy.itunes.apple.com/verifyReceipt"
APPLE_VERIFY_URL_SANDBOX = "https://sandbox.itunes.apple.com/verifyReceipt"

APPLE_PRODUCT_MONTHS = {
    "aerofit_indie_1m":  1,
    "aerofit_indie_3m":  3,
    "aerofit_indie_6m":  6,
    "aerofit_indie_12m": 12,
}

razorpay_client = razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET))
print(f"✅  Razorpay configured → key {RAZORPAY_KEY_ID[:12]}…", flush=True)

RESEND_API_KEY  = _require("RESEND_API_KEY")
RESEND_FROM     = os.environ.get("RESEND_FROM", "AERO-FIT <onboarding@resend.dev>").strip()

resend.api_key = RESEND_API_KEY

OTP_EXPIRY_MINUTES        = int(os.environ.get("OTP_EXPIRY_MINUTES", "10"))
OTP_MAX_ATTEMPTS          = int(os.environ.get("OTP_MAX_ATTEMPTS", "5"))
RESET_TOKEN_EXPIRY_MINUTES = int(os.environ.get("RESET_TOKEN_EXPIRY_MINUTES", "15"))

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
col_password_resets: Collection = mdb["password_resets"]
col_signup_otps: Collection = mdb["indie_signup_otps"]
col_indie_notifs: Collection = mdb["indie_notifications"]
col_apple_pending:      Collection = mdb["indie_apple_pending_signups"]
col_apple_transactions: Collection = mdb["indie_apple_transactions"]
col_agreements: Collection = mdb["gym_agreements"]
# ── NEW: gym-admin (website) password reset OTP/token records ───────────────
col_gym_admin_resets: Collection = mdb["gym_admin_password_resets"]

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
col_password_resets.create_index("email")
col_password_resets.create_index("expires_at")
col_signup_otps.create_index("email")
col_signup_otps.create_index("expires_at")
col_indie_notifs.create_index([("email", 1), ("sent_at", -1)])
col_indie_notifs.create_index([("email", 1), ("alert_key", 1)], unique=True)
col_indie_notifs.create_index("read")
col_apple_pending.create_index("email", unique=True)
col_apple_pending.create_index("expires_at")
col_apple_transactions.create_index("transaction_id", unique=True)
col_apple_transactions.create_index("email")
col_agreements.create_index("gym_id", unique=True)
col_agreements.create_index("agreement_id", unique=True)
col_trainers: Collection = mdb["gym_trainers"]
col_trainers.create_index([("gym_id", 1), ("created_at", DESCENDING)])
col_trainers.create_index("trainer_id", unique=True)
# ── NEW: gym-admin reset indexes ─────────────────────────────────────────────
col_gym_admin_resets.create_index("email")
col_gym_admin_resets.create_index("expires_at")
col_batches: Collection = mdb["gym_batches"]
col_batches.create_index([("gym_id", 1), ("created_at", DESCENDING)])
col_batches.create_index("batch_id", unique=True)

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
    """Android / Razorpay pricing — has the multi-month discount."""
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

def _indie_pricing_ios(months: int) -> dict:
    """iOS / Apple IAP pricing — flat ₹199/month, NO multi-month discount."""
    months    = max(1, min(months, 12))
    final_inr = round(IOS_INDIE_BASE_PRICE * months, 2)
    return {
        "months":       months,
        "base_price":   IOS_INDIE_BASE_PRICE,
        "gross_inr":    final_inr,
        "discount_pct": 0,
        "discount_inr": 0,
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

def _verify_apple_receipt(receipt_data: str) -> dict:
    if not APPLE_SHARED_SECRET:
        raise HTTPException(500, "Apple receipt verification is not configured on the server")

    payload = {
        "receipt-data": receipt_data,
        "password": APPLE_SHARED_SECRET,
        "exclude-old-transactions": True,
    }

    def _call(url: str) -> dict:
        return http_requests.post(url, json=payload, timeout=15).json()

    result = _call(APPLE_VERIFY_URL_PROD)
    if result.get("status") == 21007:
        result = _call(APPLE_VERIFY_URL_SANDBOX)

    if result.get("status") != 0:
        print(f"⚠️  Apple receipt verification failed → status={result.get('status')}", flush=True)
        raise HTTPException(400, f"Apple receipt verification failed (status {result.get('status')})")
    return result


def _find_apple_transaction(receipt_json: dict, transaction_id: str, product_id: str) -> dict:
    candidates = (
        receipt_json.get("latest_receipt_info")
        or receipt_json.get("receipt", {}).get("in_app", [])
        or []
    )
    for txn in candidates:
        if txn.get("transaction_id") == transaction_id:
            if txn.get("product_id") != product_id:
                raise HTTPException(400, "Product ID does not match the verified transaction")
            return txn
    raise HTTPException(400, "Transaction not found in verified Apple receipt")

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
    member_emails = [
        u["email"] for u in col_users.find({"gym_id": gym_id}, {"email": 1})
    ]

    users_result = col_users.delete_many({"gym_id": gym_id})

    meals_deleted = 0
    if member_emails:
        meals_result  = col_meals.delete_many({"email": {"$in": member_emails}})
        meals_deleted = meals_result.deleted_count

    scans_deleted = 0
    if member_emails:
        scans_result  = col_scan_limits.delete_many({"email": {"$in": member_emails}})
        scans_deleted = scans_result.deleted_count

    user_ids_result = col_user_ids.delete_many({"gym_id": gym_id})
    invoices_result = col_invoices.delete_many({"gym_id": gym_id})
    banners_result = col_banners.delete_many({"gym_id": gym_id})
    notifs_result = col_notifs.delete_many({"gym_id": gym_id})
    admins_result = col_gym_admins.delete_many({"gym_id": gym_id})
    batches_result = col_batches.delete_many({"gym_id": gym_id})
    trainers_result = col_trainers.delete_many({"gym_id": gym_id})
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
        "batches_deleted":  batches_result.deleted_count, 
    }
    print(
        f"🗑️  Cascade gym delete → {gym_id} | "
        f"users={summary['users_deleted']} meals={summary['meals_deleted']} "
        f"scans={summary['scans_deleted']} user_ids={summary['user_ids_deleted']} "
        f"invoices={summary['invoices_deleted']} banners={summary['banners_deleted']} "
        f"notifs={summary['notifs_deleted']} admins={summary['admins_deleted']}",
        f"batches={summary['batches_deleted']}", 
        flush=True,
    )
    return summary

# ══════════════════════════════════════════════════════════════════════════════
#  CASCADE INDIE-USER DELETE HELPER
# ══════════════════════════════════════════════════════════════════════════════

def _cascade_delete_indie_user(email: str) -> dict:
    meals_result  = col_meals.delete_many({"email": email})
    scans_result  = col_scan_limits.delete_many({"email": email})
    notifs_result = col_indie_notifs.delete_many({"email": email})
    user_result   = col_users.delete_one({"email": email})

    summary = {
        "email":         email,
        "user_deleted":  user_result.deleted_count,
        "meals_deleted": meals_result.deleted_count,
        "scans_deleted": scans_result.deleted_count,
        "notifs_deleted": notifs_result.deleted_count,
    }
    print(
        f"🗑️  Cascade indie delete → {email} | "
        f"meals={summary['meals_deleted']} scans={summary['scans_deleted']} "
        f"notifs={summary['notifs_deleted']}",
        flush=True,
    )
    return summary

# ══════════════════════════════════════════════════════════════════════════════
#  FCM PUSH SENDER (gym — topic-based)
# ══════════════════════════════════════════════════════════════════════════════

def _send_fcm_push(gym_id: str, title: str, body: str, data: dict = {}):
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
#  FCM PUSH SENDER (indie — direct device-token based)
# ══════════════════════════════════════════════════════════════════════════════

def _send_fcm_push_to_token(token: str, title: str, body: str, data: dict = {}):
    try:
        if not token:
            print("⚠️  _send_fcm_push_to_token: empty token — skipping", flush=True)
            return
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
                    "token": token,
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
            print(f"✅  FCM push (token) sent → title='{title}'", flush=True)
        else:
            print(f"⚠️  FCM token-push error {resp.status_code}: {result}", flush=True)

    except Exception as e:
        print(f"⚠️  FCM token-push failed: {e}", flush=True)


def _create_indie_alert(
    email: str,
    alert_key: str,
    title: str,
    body: str,
    alert_type: str,
    deep_link: str = "aerofit://profile/billing",
) -> bool:
    now = datetime.now(timezone.utc)
    try:
        col_indie_notifs.insert_one({
            "notification_id": str(uuid.uuid4()),
            "email":            email,
            "alert_key":        alert_key,
            "alert_type":       alert_type,
            "title":            title,
            "body":             body,
            "deep_link":        deep_link,
            "read":             False,
            "sent_at":          now,
        })
    except Exception:
        return False

    user  = col_users.find_one({"email": email}, {"fcm_token": 1})
    token = (user or {}).get("fcm_token", "")
    if token:
        _send_fcm_push_to_token(
            token, title, body,
            data={"type": alert_type, "deep_link": deep_link},
        )
    else:
        print(f"ℹ️  No fcm_token on file for {email} — in-app alert created, push skipped", flush=True)

    print(f"✅  Indie alert created → {email} | {alert_key}", flush=True)
    return True


def _generate_otp() -> str:
    return f"{random.randint(0, 999999):06d}"


def _send_otp_email(to_email: str, name: str, otp: str) -> bool:
    try:
        resend.Emails.send({
            "from":    RESEND_FROM,
            "to":      [to_email],
            "subject": f"Your AERO-FIT password reset code: {otp}",
            "html": f"""
                <div style="font-family: -apple-system, Arial, sans-serif; max-width: 480px; margin: 0 auto; padding: 24px;">
                    <h2 style="color:#0A1628; margin-bottom: 4px;">AERO<span style="color:#2A5FD4;">-FIT</span></h2>
                    <p style="color:#3A5A8A; font-size: 15px;">Hi {name or 'there'},</p>
                    <p style="color:#3A5A8A; font-size: 15px;">
                        Use the code below to reset your password. It expires in {OTP_EXPIRY_MINUTES} minutes.
                    </p>
                    <div style="background:#F0F6FF; border-radius:12px; padding:18px; text-align:center; margin: 20px 0;">
                        <span style="font-size: 32px; font-weight: 800; letter-spacing: 6px; color:#0A1628;">{otp}</span>
                    </div>
                    <p style="color:#8AAAD0; font-size: 13px;">
                        If you didn't request this, you can safely ignore this email.
                    </p>
                </div>
            """,
        })
        return True
    except Exception as e:
        print(f"⚠️  Failed to send OTP email to {to_email}: {e}", flush=True)
        return False


def _generate_reset_token() -> str:
    return str(uuid.uuid4())

# ══════════════════════════════════════════════════════════════════════════════
#  BACKGROUND THREADS
# ══════════════════════════════════════════════════════════════════════════════

def _keep_alive():
    time.sleep(120)
    while True:
        try:
            import requests as _req
            _req.get("https://aero-fit-backend.onrender.com/health", timeout=5)
            print("✅  Keep-alive ping sent", flush=True)
        except Exception as e:
            print(f"⚠️  Keep-alive failed: {e}", flush=True)
        time.sleep(300)


def _run_expiry_job():
    time.sleep(30)
    while True:
        try:
            now = datetime.now(timezone.utc)

            _cleanup_old_billing_alerts(now)

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

            soon_cutoff = now + timedelta(days=3)
            expiring_soon = list(col_users.find({
                "indie_plan":         True,
                "membership_expired": {"$ne": True},
                "indie_expires_at":   {"$lte": soon_cutoff, "$gt": now},
            }))

            for u in expiring_soon:
                exp = _ensure_utc(u["indie_expires_at"])
                days_left = max(0, (exp - now).days)
                alert_key = f"expiring_soon_{exp.strftime('%Y-%m-%d')}"
                _create_indie_alert(
                    email=u["email"],
                    alert_key=alert_key,
                    alert_type="expiring_soon",
                    title="⏳ Your AERO-FIT plan ends soon",
                    body=(
                        f"Your plan expires in {days_left} day{'s' if days_left != 1 else ''}. "
                        "Extend it from your Profile to avoid losing access."
                    ),
                )

            newly_expired_indie = list(col_users.find({
                "indie_plan":         True,
                "membership_expired": {"$ne": True},
                "indie_expires_at":   {"$lte": now},
            }))

            if newly_expired_indie:
                print(f"⏰  Expiry job: {len(newly_expired_indie)} indie user(s) entering grace period", flush=True)

            for u in newly_expired_indie:
                grace_ends = now + timedelta(days=2)
                col_users.update_one(
                    {"email": u["email"]},
                    {"$set": {
                        "membership_expired":    True,
                        "membership_expired_at": now,
                        "grace_period_ends_at":  grace_ends,
                    }}
                )
                print(f"   ↳ Indie user entered grace period: {u['email']} (deletes after {grace_ends.isoformat()})", flush=True)

                _create_indie_alert(
                    email=u["email"],
                    alert_key=f"grace_period_{grace_ends.strftime('%Y-%m-%d')}",
                    alert_type="grace_period",
                    title="🚨 Your AERO-FIT plan has expired",
                    body=(
                        "Renew within 2 days from your Profile or your account "
                        "and all data will be permanently deleted."
                    ),
                )

            expired_trials = list(col_gyms.find({
                "status":            "trial",
                "trial_expires_at":  {"$lte": now},
            }))

            if expired_trials:
                print(f"🗑️  Expiry job: {len(expired_trials)} trial gym(s) past 14 days — deleting", flush=True)

            for gym in expired_trials:
                gid = gym.get("gym_id")
                print(f"   ↳ Auto-deleting expired trial gym: {gym.get('name')} ({gid})", flush=True)
                _cascade_delete_gym(gid)

            to_delete = list(col_users.find({
                "indie_plan":           True,
                "membership_expired":   True,
                "grace_period_ends_at": {"$lte": now},
            }))

            if to_delete:
                print(f"🗑️  Expiry job: {len(to_delete)} indie user(s) past grace period — deleting", flush=True)

            for u in to_delete:
                _cascade_delete_indie_user(u["email"])

        except Exception as e:
            print(f"⚠️  Expiry job error: {e}", flush=True)

        time.sleep(3600)


def _run_pro_billing_job():
    time.sleep(60)
    while True:
        try:
            now = datetime.now(timezone.utc)
            pro_gyms = list(col_gyms.find({
                "plan": "Pro",
                "pro_fee_paid": True,
                "billing_cycle_next_invoice_at": {"$exists": True, "$ne": None},
            }))

            for gym in pro_gyms:
                gym_id = gym["gym_id"]
                next_invoice_at = _ensure_utc(gym.get("billing_cycle_next_invoice_at"))
                if not next_invoice_at:
                    continue

                reminder_at = next_invoice_at - timedelta(days=2)
                already_invoiced = gym.get("billing_cycle_last_invoiced_for") == next_invoice_at.isoformat()

                if now >= reminder_at and not already_invoiced:
                    member_count = col_user_ids.count_documents({"gym_id": gym_id, "status": "used"})
                    if member_count > 0:
                        gross = round(AEROFIT_FEE_PER_USER * member_count, 2)
                        invoice_id = str(uuid.uuid4())
                        inv_number = _invoice_number()
                        col_invoices.insert_one({
                            "invoice_id":       invoice_id,
                            "invoice_number":   inv_number,
                            "gym_id":           gym_id,
                            "gym_name":         gym["name"],
                            "admin_email":      gym.get("admin_email", ""),
                            "period":           next_invoice_at.strftime("%B %Y"),
                            "member_count":     member_count,
                            "fee_per_user":     AEROFIT_FEE_PER_USER,
                            "gross":            gross,
                            "status":           "pending",
                            "notes":            "Auto-generated monthly Pro billing",
                            "created_at":       now,
                            "due_at":           next_invoice_at,
                            "paid_at":          None,
                            "payment_ref":      None,
                            "alerts":           [],
                            "auto_generated":   True,
                        })
                        col_notifs.insert_one({
                            "notification_id": str(uuid.uuid4()),
                            "gym_id":          gym_id,
                            "title":           f"💳 Monthly invoice — {inv_number}",
                            "body":            f"Your monthly Aerofit invoice for {member_count} member(s) is ₹{gross:,.0f}, due {next_invoice_at.strftime('%d %b %Y')}.",
                            "type":            "billing",
                            "segments":        ["admin"],
                            "deep_link":       f"aerofit://billing/invoice/{invoice_id}",
                            "scheduled_at":    "",
                            "sent_at":         now,
                            "invoice_id":      invoice_id,
                            "read":            False,
                        })
                        print(f"✅  Auto-invoice created → {inv_number}  gym={gym_id}  {member_count} members  ₹{gross}", flush=True)
                    else:
                        print(f"ℹ️  Skipped auto-invoice for {gym_id} — no active members yet", flush=True)

                    col_gyms.update_one(
                        {"gym_id": gym_id},
                        {"$set": {"billing_cycle_last_invoiced_for": next_invoice_at.isoformat()}},
                    )

                if now >= next_invoice_at:
                    new_next = next_invoice_at + timedelta(days=30)
                    col_gyms.update_one(
                        {"gym_id": gym_id},
                        {"$set": {"billing_cycle_next_invoice_at": new_next}},
                    )
                    print(f"🔄  Billing cycle rolled forward → gym={gym_id}  next cycle ends {new_next.isoformat()}", flush=True)

        except Exception as e:
            print(f"⚠️  Pro billing job error: {e}", flush=True)

        time.sleep(21600)  # every 6 hours


threading.Thread(target=_keep_alive,          daemon=True).start()
threading.Thread(target=_run_expiry_job,      daemon=True).start()
threading.Thread(target=_run_pro_billing_job, daemon=True).start()
print("✅  Background threads started (keep-alive + expiry job + pro billing job)", flush=True)

# ══════════════════════════════════════════════════════════════════════════════
#  FASTAPI APP
# ══════════════════════════════════════════════════════════════════════════════

app = FastAPI(title="AERO-FIT API", version="20.1.2")

ALLOWED_ORIGINS = [
    "http://localhost:5173", "http://localhost:5174", "http://localhost:3000",
    "http://127.0.0.1:5173", "http://127.0.0.1:5174", "http://127.0.0.1:3000",
    "https://aryan212004.github.io",
    "https://myfittt.com",
    "https://www.myfittt.com",
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

class DeleteAccountRequest(BaseModel):
    password: str

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
    gym_id:    str
    period:    str
    notes:     Optional[str] = ""
    gross_override: Optional[float] = None 

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

# ── Gym invoice payment (Razorpay — gym admin pays Aerofit) ──────────────────
class InvoicePaymentVerify(BaseModel):
    razorpay_order_id:   str
    razorpay_payment_id: str
    razorpay_signature:  str

class FcmTokenUpdate(BaseModel):
    fcm_token: str
    gym_id:    str

# ── Indie (independent) payment models — Android / Razorpay ─────────────────
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
    months:   int

class ForgotPasswordRequest(BaseModel):
    email: str

class VerifyOtpRequest(BaseModel):
    email: str
    otp:   str

class ResetPasswordRequest(BaseModel):
    email:        str
    reset_token:  str
    new_password: str

class IndieSendOtpRequest(BaseModel):
    email: str

class IndieVerifySignupOtpRequest(BaseModel):
    email: str
    otp:   str

class ProActivationVerify(BaseModel):
    razorpay_order_id:   str
    razorpay_payment_id: str
    razorpay_signature:  str

# ── Indie (independent) payment models — iOS / Apple IAP ────────────────────
class ApplePrepareSignupRequest(BaseModel):
    email:     str
    name:      str
    password:  str
    weight_kg: float
    height_cm: float

class AppleVerifyRequest(BaseModel):
    email:          str
    receipt_data:   str
    product_id:     str
    transaction_id: str

# ── Gym Partnership Agreement (website / admin dashboard only) ──────────────
class AgreementSubmit(BaseModel):
    admin_name:        str
    gym_name:          str
    id_type:           str   # "Aadhar" | "Driving License" | "Other"
    id_number:         str
    signature_base64:  str
    id_proof_base64:   str

# ── NEW: Gym admin (website) password reset models ──────────────────────────
class GymAdminForgotPasswordRequest(BaseModel):
    email: str

class GymAdminVerifyOtpRequest(BaseModel):
    email: str
    otp:   str

class GymAdminResetPasswordRequest(BaseModel):
    email:        str
    reset_token:  str
    new_password: str

class TrainerCreate(BaseModel):
    name:            str
    specialty:       str
    experience_years: int = 0
    phone:           str = ""
    certifications:  list[str] = []

class TrainerUpdate(BaseModel):
    name:             Optional[str]       = None
    specialty:        Optional[str]       = None
    experience_years: Optional[int]       = None
    phone:            Optional[str]       = None
    certifications:   Optional[list[str]] = None

# ── Pydantic models — add near your other model definitions ─────────────────
class BatchCreate(BaseModel):
    name:         str
    time:         str            # e.g. "6:00 – 7:30 AM"
    days_label:   str            # e.g. "Mon · Wed · Fri"
    trainer_name: str
    capacity:     int = 20
    member_count: int = 0

class BatchUpdate(BaseModel):
    name:         Optional[str] = None
    time:         Optional[str] = None
    days_label:   Optional[str] = None
    trainer_name: Optional[str] = None
    capacity:     Optional[int] = None
    member_count: Optional[int] = None

# ── NEW: Workout Access lock (gym admin toggles per-member Plans visibility) ─
class WorkoutLockUpdate(BaseModel):
    locked: bool

# ══════════════════════════════════════════════════════════════════════════════
#  ROUTES — HEALTH
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/health")
def health():
    return {
        "status":         "ok",
        "version":        "20.1.2",
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
#  ROUTES — GYM ADMIN PASSWORD RESET (website — separate from app /auth/*)
#  Uses its own gym_admin_password_resets collection so a gym admin and an
#  app user sharing the same email never collide on reset tokens.
# ══════════════════════════════════════════════════════════════════════════════

@app.post("/gym-admin/forgot-password")
def gym_admin_forgot_password(req: GymAdminForgotPasswordRequest):
    email = req.email.strip().lower()
    if not re.match(r"^[\w\.-]+@[\w\.-]+\.\w{2,}$", email):
        raise HTTPException(400, "Invalid email address")

    admin = col_gym_admins.find_one({"email": email})
    generic_response = {
        "status":  "ok",
        "message": "If an admin account exists for this email, an OTP has been sent.",
    }
    if not admin:
        print(f"ℹ️  Gym-admin forgot-password requested for non-existent email: {email}", flush=True)
        return generic_response

    if admin.get("status") == "inactive":
        # Don't leak account status either — behave identically either way.
        print(f"ℹ️  Gym-admin forgot-password requested for inactive admin: {email}", flush=True)
        return generic_response

    now = datetime.now(timezone.utc)
    otp = _generate_otp()

    col_gym_admin_resets.delete_many({"email": email, "used": False})
    col_gym_admin_resets.insert_one({
        "email":       email,
        "otp":         otp,
        "attempts":    0,
        "used":        False,
        "reset_token": None,
        "created_at":  now,
        "expires_at":  now + timedelta(minutes=OTP_EXPIRY_MINUTES),
    })

    sent = _send_otp_email(email, admin.get("name", ""), otp)
    if not sent:
        print(f"⚠️  Gym-admin OTP generated but email send failed for {email}", flush=True)

    print(f"✅  Gym-admin OTP issued → {email}", flush=True)
    return generic_response


@app.post("/gym-admin/verify-otp")
def gym_admin_verify_otp(req: GymAdminVerifyOtpRequest):
    email = req.email.strip().lower()
    otp   = req.otp.strip()

    record = col_gym_admin_resets.find_one({"email": email, "used": False})
    if not record:
        raise HTTPException(400, "No pending reset request for this email. Please request a new OTP.")

    now = datetime.now(timezone.utc)
    if _ensure_utc(record["expires_at"]) <= now:
        col_gym_admin_resets.delete_one({"_id": record["_id"]})
        raise HTTPException(400, "OTP has expired. Please request a new one.")

    if record.get("attempts", 0) >= OTP_MAX_ATTEMPTS:
        col_gym_admin_resets.delete_one({"_id": record["_id"]})
        raise HTTPException(429, "Too many incorrect attempts. Please request a new OTP.")

    if record["otp"] != otp:
        col_gym_admin_resets.update_one(
            {"_id": record["_id"]},
            {"$inc": {"attempts": 1}},
        )
        remaining = OTP_MAX_ATTEMPTS - (record.get("attempts", 0) + 1)
        raise HTTPException(400, f"Incorrect OTP. {max(0, remaining)} attempt(s) remaining.")

    reset_token = _generate_reset_token()
    col_gym_admin_resets.update_one(
        {"_id": record["_id"]},
        {"$set": {
            "reset_token":         reset_token,
            "reset_token_expires": now + timedelta(minutes=RESET_TOKEN_EXPIRY_MINUTES),
        }},
    )

    print(f"✅  Gym-admin OTP verified → {email}", flush=True)
    return {"status": "ok", "reset_token": reset_token}


@app.post("/gym-admin/reset-password")
def gym_admin_reset_password(req: GymAdminResetPasswordRequest):
    email = req.email.strip().lower()

    if len(req.new_password.strip()) < 6:
        raise HTTPException(400, "Password must be at least 6 characters")

    record = col_gym_admin_resets.find_one({
        "email":       email,
        "used":        False,
        "reset_token": req.reset_token,
    })
    if not record:
        raise HTTPException(400, "Invalid or expired reset session. Please start over.")

    now = datetime.now(timezone.utc)
    token_expiry = record.get("reset_token_expires")
    if not token_expiry or _ensure_utc(token_expiry) <= now:
        col_gym_admin_resets.delete_one({"_id": record["_id"]})
        raise HTTPException(400, "Reset session expired. Please start over.")

    admin = col_gym_admins.find_one({"email": email})
    if not admin:
        raise HTTPException(404, "Admin not found")

    hashed = bcrypt.hashpw(req.new_password.strip().encode(), bcrypt.gensalt()).decode()
    col_gym_admins.update_one({"email": email}, {"$set": {"password": hashed}})

    col_gym_admin_resets.update_one(
        {"_id": record["_id"]},
        {"$set": {"used": True, "used_at": now}},
    )

    print(f"✅  Gym-admin password reset completed → {email}", flush=True)
    return {"status": "ok", "message": "Password reset successful. Please sign in."}

@app.post("/gym/{gym_id}/trainers")
def create_trainer(gym_id: str, req: TrainerCreate):
    if not col_gyms.find_one({"gym_id": gym_id}):
        raise HTTPException(404, "Gym not found")
    if not req.name.strip():
        raise HTTPException(400, "Trainer name is required")

    trainer_id = str(uuid.uuid4())
    doc = {
        "trainer_id":       trainer_id,
        "gym_id":           gym_id,
        "name":             req.name.strip(),
        "specialty":        req.specialty.strip(),
        "experience_years": max(0, req.experience_years),
        "phone":            req.phone.strip(),
        "certifications":   [c.strip() for c in req.certifications if c.strip()],
        "created_at":       datetime.now(timezone.utc),
    }
    col_trainers.insert_one(doc)
    print(f"✅  Trainer created → {trainer_id}  gym={gym_id}  '{req.name}'", flush=True)
    return {"status": "created", "trainer_id": trainer_id}

@app.get("/gym/{gym_id}/trainers")
def list_trainers(gym_id: str):
    if not col_gyms.find_one({"gym_id": gym_id}):
        raise HTTPException(404, "Gym not found")
    docs = list(col_trainers.find({"gym_id": gym_id}).sort("created_at", DESCENDING))
    return [_doc(d) for d in docs]

@app.patch("/gym/{gym_id}/trainers/{trainer_id}")
def update_trainer(gym_id: str, trainer_id: str, req: TrainerUpdate):
    trainer = col_trainers.find_one({"trainer_id": trainer_id, "gym_id": gym_id})
    if not trainer:
        raise HTTPException(404, "Trainer not found for this gym")

    update: dict = {}
    if req.name             is not None: update["name"]             = req.name.strip()
    if req.specialty        is not None: update["specialty"]        = req.specialty.strip()
    if req.experience_years is not None: update["experience_years"] = max(0, req.experience_years)
    if req.phone            is not None: update["phone"]            = req.phone.strip()
    if req.certifications   is not None: update["certifications"]   = [c.strip() for c in req.certifications if c.strip()]

    if update:
        col_trainers.update_one({"trainer_id": trainer_id, "gym_id": gym_id}, {"$set": update})
    return {"status": "updated", "trainer_id": trainer_id}

@app.delete("/gym/{gym_id}/trainers/{trainer_id}")
def delete_trainer(gym_id: str, trainer_id: str):
    result = col_trainers.delete_one({"trainer_id": trainer_id, "gym_id": gym_id})
    if result.deleted_count == 0:
        raise HTTPException(404, "Trainer not found or belongs to a different gym")
    return {"status": "deleted"}

# ══════════════════════════════════════════════════════════════════════════════
#  ROUTES — BATCHES
# ══════════════════════════════════════════════════════════════════════════════

@app.post("/gym/{gym_id}/batches")
def create_batch(gym_id: str, req: BatchCreate):
    if not col_gyms.find_one({"gym_id": gym_id}):
        raise HTTPException(404, "Gym not found")
    if not req.name.strip():
        raise HTTPException(400, "Batch name is required")

    batch_id = str(uuid.uuid4())
    doc = {
        "batch_id":     batch_id,
        "gym_id":       gym_id,
        "name":         req.name.strip(),
        "time":         req.time.strip(),
        "days_label":   req.days_label.strip(),
        "trainer_name": req.trainer_name.strip(),
        "capacity":     max(1, req.capacity),
        "enrolled_emails": [],   
        "member_count": max(0, req.member_count),
        "created_at":   datetime.now(timezone.utc),
    }
    col_batches.insert_one(doc)
    print(f"✅  Batch created → {batch_id}  gym={gym_id}  '{req.name}'", flush=True)
    return {"status": "created", "batch_id": batch_id}

@app.get("/gym/{gym_id}/batches")
def list_batches(gym_id: str):
    if not col_gyms.find_one({"gym_id": gym_id}):
        raise HTTPException(404, "Gym not found")
    docs = list(col_batches.find({"gym_id": gym_id}).sort("created_at", DESCENDING))
    return [_doc(d) for d in docs]

@app.patch("/gym/{gym_id}/batches/{batch_id}")
def update_batch(gym_id: str, batch_id: str, req: BatchUpdate):
    batch = col_batches.find_one({"batch_id": batch_id, "gym_id": gym_id})
    if not batch:
        raise HTTPException(404, "Batch not found for this gym")

    update: dict = {}
    if req.name         is not None: update["name"]         = req.name.strip()
    if req.time         is not None: update["time"]         = req.time.strip()
    if req.days_label   is not None: update["days_label"]   = req.days_label.strip()
    if req.trainer_name is not None: update["trainer_name"] = req.trainer_name.strip()
    if req.capacity     is not None: update["capacity"]     = max(1, req.capacity)
    if req.member_count is not None: update["member_count"] = max(0, req.member_count)

    if update:
        col_batches.update_one({"batch_id": batch_id, "gym_id": gym_id}, {"$set": update})
    return {"status": "updated", "batch_id": batch_id}

@app.delete("/gym/{gym_id}/batches/{batch_id}")
def delete_batch(gym_id: str, batch_id: str):
    result = col_batches.delete_one({"batch_id": batch_id, "gym_id": gym_id})
    if result.deleted_count == 0:
        raise HTTPException(404, "Batch not found or belongs to a different gym")
    return {"status": "deleted"}

class BatchEnroll(BaseModel):
    email: str

@app.post("/gym/{gym_id}/batches/{batch_id}/enroll")
def enroll_in_batch(gym_id: str, batch_id: str, req: BatchEnroll):
    email = req.email.strip().lower()

    member = col_users.find_one({"email": email, "gym_id": gym_id})
    if not member:
        raise HTTPException(404, "Member not found for this gym")

    batch = col_batches.find_one({"batch_id": batch_id, "gym_id": gym_id})
    if not batch:
        raise HTTPException(404, "Batch not found for this gym")

    enrolled = batch.get("enrolled_emails", [])
    if email in enrolled:
        return {"status": "already_enrolled", "batch_id": batch_id}

    if len(enrolled) >= batch.get("capacity", 20):
        raise HTTPException(400, "This batch is full")

    col_batches.update_one(
        {"batch_id": batch_id, "gym_id": gym_id},
        {
            "$addToSet": {"enrolled_emails": email},
            "$inc": {"member_count": 1},
        },
    )
    print(f"✅  {email} enrolled in batch {batch_id}  gym={gym_id}", flush=True)
    return {"status": "enrolled", "batch_id": batch_id}


@app.post("/gym/{gym_id}/batches/{batch_id}/unenroll")
def unenroll_from_batch(gym_id: str, batch_id: str, req: BatchEnroll):
    email = req.email.strip().lower()

    batch = col_batches.find_one({"batch_id": batch_id, "gym_id": gym_id})
    if not batch:
        raise HTTPException(404, "Batch not found for this gym")

    if email not in batch.get("enrolled_emails", []):
        return {"status": "not_enrolled", "batch_id": batch_id}

    col_batches.update_one(
        {"batch_id": batch_id, "gym_id": gym_id},
        {
            "$pull": {"enrolled_emails": email},
            "$inc": {"member_count": -1},
        },
    )
    print(f"✅  {email} left batch {batch_id}  gym={gym_id}", flush=True)
    return {"status": "unenrolled", "batch_id": batch_id}

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
    trial_expires_at = (now + timedelta(days=14)) if req.plan == "Trial" else None

    col_gyms.insert_one({
        "gym_id":            gym_id,
        "name":              req.name.strip(),
        "city":              req.city.strip(),
        "plan":              req.plan,
        "status":            "trial" if req.plan == "Trial" else "active",
        "members":           0,
        "revenue":           0,
        "price_per_user":    req.price_per_user,
        "admin_email":       admin_email,
        "admin_id":          admin_id,
        "trial_expires_at":  trial_expires_at,
        "pro_fee_paid":      False,
        "pro_fee_paid_at":   None,
        "pro_fee_expires_at": None,
        "pro_activation_razorpay_order_id": None,
        "pro_activation_order_created_at":  None,
        "pro_fee_last_payment_ref": None,
        "billing_cycle_start":              None,
        "billing_cycle_next_invoice_at":    None,
        "billing_cycle_last_invoiced_for":  None,
        "created_at":        now,
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
    gym = col_gyms.find_one({"gym_id": gym_id})
    if not gym:
        raise HTTPException(404, "Gym not found")

    member_count   = col_users.count_documents({"gym_id": gym_id})
    user_id_count  = col_user_ids.count_documents({"gym_id": gym_id})
    invoice_count  = col_invoices.count_documents({"gym_id": gym_id})
    banner_count   = col_banners.count_documents({"gym_id": gym_id})
    notif_count    = col_notifs.count_documents({"gym_id": gym_id})
    admin_count    = col_gym_admins.count_documents({"gym_id": gym_id})

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
    if not col_gyms.find_one({"gym_id": gym_id}):
        raise HTTPException(404, "Gym not found")

    summary = _cascade_delete_gym(gym_id)

    return {
        "status":  "deleted",
        "gym_id":  gym_id,
        "deleted": summary,
    }

# ══════════════════════════════════════════════════════════════════════════════
#  ROUTES — PRO PLAN ACTIVATION
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/gym/{gym_id}/pro-activation-status")
def pro_activation_status(gym_id: str):
    gym = col_gyms.find_one({"gym_id": gym_id})
    if not gym:
        raise HTTPException(404, "Gym not found")

    if gym.get("plan") != "Pro":
        return {"required": False}

    now        = datetime.now(timezone.utc)
    paid       = gym.get("pro_fee_paid", False)
    expires_at = _ensure_utc(gym.get("pro_fee_expires_at"))

    if paid and expires_at and expires_at > now:
        days_left = (expires_at - now).days
        return {
            "required":      False,
            "expires_at":    _fmt_dt(expires_at),
            "days_left":     days_left,
            "expiring_soon": days_left <= 15,
        }

    return {
        "required": True,
        "amount":   PRO_ACTIVATION_FEE_INR,
        "expired":  bool(paid and expires_at and expires_at <= now),
    }


@app.post("/gym/{gym_id}/pro-activation/create-order")
def pro_activation_create_order(gym_id: str):
    gym = col_gyms.find_one({"gym_id": gym_id})
    if not gym:
        raise HTTPException(404, "Gym not found")
    if gym.get("plan") != "Pro":
        raise HTTPException(400, "Activation fee only applies to Pro plan gyms")

    now        = datetime.now(timezone.utc)
    expires_at = _ensure_utc(gym.get("pro_fee_expires_at"))
    if gym.get("pro_fee_paid") and expires_at and expires_at > now:
        raise HTTPException(400, "Pro plan is already active")

    admin = col_gym_admins.find_one({"gym_id": gym_id})

    existing_order_id = gym.get("pro_activation_razorpay_order_id")
    if existing_order_id:
        try:
            rp_order = razorpay_client.order.fetch(existing_order_id)
            if rp_order.get("status") == "created":
                return {
                    "order_id":      existing_order_id,
                    "key_id":        RAZORPAY_KEY_ID,
                    "amount":        rp_order["amount"],
                    "currency":      "INR",
                    "name":          "AERO-FIT",
                    "description":   f"Pro Plan Activation — {gym['name']} (1 year)",
                    "prefill_email": (admin or {}).get("email", gym.get("admin_email", "")),
                    "prefill_name":  gym.get("name", ""),
                }
        except Exception:
            pass

    amount_paise = int(round(PRO_ACTIVATION_FEE_INR * 100))

    try:
        rp_order = razorpay_client.order.create({
            "amount":   amount_paise,
            "currency": "INR",
            "receipt":  f"proact_{gym_id[:16]}_{now.strftime('%m%d%H%M%S')}",
            "notes":    {"gym_id": gym_id, "purpose": "pro_activation"},
        })
    except Exception as e:
        print(f"❌  Razorpay pro-activation order creation failed: {e}", flush=True)
        raise HTTPException(502, "Payment gateway error. Please try again.")

    order_id = rp_order["id"]
    col_gyms.update_one(
        {"gym_id": gym_id},
        {"$set": {
            "pro_activation_razorpay_order_id": order_id,
            "pro_activation_order_created_at":  now,
        }},
    )

    print(f"✅  Pro activation order created → {order_id}  gym={gym_id}  ₹{PRO_ACTIVATION_FEE_INR}", flush=True)
    return {
        "order_id":      order_id,
        "key_id":        RAZORPAY_KEY_ID,
        "amount":        amount_paise,
        "currency":      "INR",
        "name":          "AERO-FIT",
        "description":   f"Pro Plan Activation — {gym['name']} (1 year)",
        "prefill_email": (admin or {}).get("email", gym.get("admin_email", "")),
        "prefill_name":  gym.get("name", ""),
    }

# ══════════════════════════════════════════════════════════════════════════════
#  ROUTES — WORKOUT ACCESS (gym admin locks/unlocks the Workout Plans screen
#  for individual members; Batches and Trainers are never affected)
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/gym/{gym_id}/members")
def list_members(gym_id: str):
    if not col_gyms.find_one({"gym_id": gym_id}):
        raise HTTPException(404, "Gym not found")
    docs = list(col_users.find({"gym_id": gym_id}).sort("created_at", DESCENDING))
    return [
        {
            "email": d["email"],
            "name": d.get("name", ""),
            "workout_plans_locked": d.get("workout_plans_locked", False),
        }
        for d in docs
    ]

@app.patch("/gym/{gym_id}/members/{email}/workout-lock")
def set_workout_lock(gym_id: str, email: str, req: WorkoutLockUpdate):
    email = email.strip().lower()
    member = col_users.find_one({"email": email, "gym_id": gym_id})
    if not member:
        raise HTTPException(404, "Member not found for this gym")

    col_users.update_one(
        {"email": email},
        {"$set": {
            "workout_plans_locked": req.locked,
            "updated_at":           datetime.now(timezone.utc),
        }},
    )
    print(f"✅  Workout Plans {'locked' if req.locked else 'unlocked'} → {email}  gym={gym_id}", flush=True)
    return {"email": email, "workout_plans_locked": req.locked}

# Lightweight — this is the one the Flutter app polls
@app.get("/user/{email}/workout-access")
def get_workout_access(email: str):
    user = col_users.find_one({"email": email.strip().lower()})
    if not user:
        raise HTTPException(404, "User not found")
    return {"locked": bool(user.get("workout_plans_locked", False))}

@app.post("/gym/{gym_id}/pro-activation/reset-order")
def pro_activation_reset_order(gym_id: str, req: AlphaLogin):
    """Alpha-admin only: clears a gym's cached Razorpay pro-activation order
    so a fresh one is created at the current PRO_ACTIVATION_FEE_INR. Useful
    if a gym's order was created before a price change and needs to be
    regenerated. Requires alpha-admin credentials — see /alpha/login."""
    if req.username != ALPHA_USERNAME or req.password != ALPHA_PASSWORD:
        raise HTTPException(401, "Invalid alpha admin credentials")

    if not col_gyms.find_one({"gym_id": gym_id}):
        raise HTTPException(404, "Gym not found")

    result = col_gyms.update_one(
        {"gym_id": gym_id},
        {"$unset": {
            "pro_activation_razorpay_order_id": "",
            "pro_activation_order_created_at": "",
        }},
    )
    print(f"✅  Pro-activation order reset by alpha admin → gym={gym_id}", flush=True)
    return {"status": "ok", "matched": result.matched_count}


@app.post("/gym/{gym_id}/pro-activation/verify-payment")
def pro_activation_verify_payment(gym_id: str, req: ProActivationVerify):
    if not _verify_hmac(req.razorpay_order_id, req.razorpay_payment_id, req.razorpay_signature):
        raise HTTPException(400, "Payment verification failed. Signature mismatch.")

    gym = col_gyms.find_one({"gym_id": gym_id})
    if not gym:
        raise HTTPException(404, "Gym not found")

    if gym.get("pro_activation_razorpay_order_id") != req.razorpay_order_id:
        raise HTTPException(400, "Order ID does not match this gym's activation order")

    now            = datetime.now(timezone.utc)
    current_expiry = _ensure_utc(gym.get("pro_fee_expires_at"))
    base       = current_expiry if (current_expiry and current_expiry > now) else now
    new_expiry = base + timedelta(days=365)

    update_fields = {
        "pro_fee_paid":             True,
        "pro_fee_paid_at":          now,
        "pro_fee_expires_at":       new_expiry,
        "pro_fee_last_payment_ref": req.razorpay_payment_id,
    }

    if not gym.get("billing_cycle_start"):
        update_fields["billing_cycle_start"]           = now
        update_fields["billing_cycle_next_invoice_at"] = now + timedelta(days=30)
        print(f"✅  Monthly billing cycle started → gym={gym_id}  first invoice due {(now + timedelta(days=30)).isoformat()}", flush=True)

    col_gyms.update_one({"gym_id": gym_id}, {"$set": update_fields})

    print(f"✅  Pro activation paid → gym={gym_id}  pid={req.razorpay_payment_id}  valid until {new_expiry.isoformat()}", flush=True)
    return {
        "status":     "activated",
        "gym_id":     gym_id,
        "expires_at": new_expiry.isoformat(),
    }

# ══════════════════════════════════════════════════════════════════════════════
#  ROUTES — GYM PARTNERSHIP AGREEMENT
# ══════════════════════════════════════════════════════════════════════════════

AGREEMENT_TEXT = """GYM PARTNERSHIP & SERVICE AGREEMENT

This Agreement is entered into on {agreement_date} between:

AERO-VISUALS (The Company), the owner and operator of the AERO-FIT application,
AND
{gym_name} ("Gym/Admin"), represented by {admin_name}, holding identification
proof: {id_type} (ID No: {id_number_masked}).

1. PRO ACTIVATION FEE
The Gym/Admin has paid a one-time Pro Activation Fee (Rs.5000) to activate Pro/Gym
Management features on the AERO-FIT platform. This fee is strictly
NON-REFUNDABLE under any circumstances, including account termination,
service dissatisfaction, or discontinuation of use.

2. MONTHLY SUBSCRIPTION FEE
The Gym/Admin agrees to pay a recurring monthly fee of Rs.{monthly_fee} per
active registered user/member under the Gym's account, billed monthly based
on active user count. Non-payment may result in suspension of Gym features
until dues are cleared.

3. SCOPE OF SERVICES
Aero-Visuals shall provide access to the AERO-FIT Gym Management Dashboard,
member tracking, AI-based meal scanning, workout guidance, activity
tracking, and related features as available on the platform.

4. RESPONSIBILITIES OF THE GYM/ADMIN
a. Provide accurate gym and identification information.
b. Ensure timely payment of monthly subscription fees.
c. Use the platform in compliance with applicable laws.
d. Not misuse, resell, or unauthorizedly redistribute platform access.

5. TERM & TERMINATION
This Agreement remains valid as long as the Gym/Admin account is active on
AERO-FIT. Either party may terminate this agreement with written notice;
however, the Pro Activation Fee remains non-refundable regardless of
termination timing.

6. DATA & PRIVACY
Identification and signature data collected are used solely for
verification and legal record-keeping purposes, governed by Aero-Visuals'
Privacy Policy.

7. GOVERNING LAW
This Agreement shall be governed by the laws of India.

By signing below, the Gym/Admin acknowledges having read, understood, and
agreed to all terms stated above.

Admin Name: {admin_name}
Gym Name: {gym_name}
Date: {agreement_date}
ID Proof Type: {id_type}
"""

def _mask_id(id_number: str) -> str:
    id_number = id_number.strip()
    if len(id_number) <= 4:
        return "*" * len(id_number)
    return id_number[:2] + "*" * (len(id_number) - 4) + id_number[-2:]

def _pdf_safe(text: str) -> str:
    """
    fpdf2's core Helvetica font only supports Latin-1. Any character outside
    that range (₹, emoji, curly quotes, non-Latin scripts, etc.) crashes
    multi_cell() with a Unicode encoding error. Since gym_name and admin_name
    are free-text user input (and could theoretically contain such
    characters even after the ₹ literal below is fixed), sanitize before
    handing text to fpdf so a stray character can never 500 this endpoint.
    """
    return text.encode("latin-1", errors="replace").decode("latin-1")

def _generate_agreement_pdf(gym_name: str, admin_name: str, id_type: str,
                             id_number_masked: str, signature_local_path: str,
                             agreement_date: str) -> bytes:
    from fpdf import FPDF

    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(0, 10, "AERO-VISUALS - Gym App Partnership Agreement", ln=True, align="C")
    pdf.ln(4)
    pdf.set_font("Helvetica", "", 10.5)

    body = AGREEMENT_TEXT.format(
        agreement_date=agreement_date,
        gym_name=gym_name,
        admin_name=admin_name,
        id_type=id_type,
        id_number_masked=id_number_masked,
        monthly_fee=int(AEROFIT_FEE_PER_USER),
    )
    pdf.multi_cell(0, 5.5, _pdf_safe(body))

    if signature_local_path and os.path.exists(signature_local_path):
        pdf.ln(4)
        pdf.set_font("Helvetica", "B", 10.5)
        pdf.cell(0, 6, "Signature:", ln=True)
        pdf.image(signature_local_path, w=60)

    out = pdf.output(dest="S")
    return bytes(out)


@app.get("/gym/{gym_id}/agreement-status")
def agreement_status(gym_id: str):
    gym = col_gyms.find_one({"gym_id": gym_id})
    if not gym:
        raise HTTPException(404, "Gym not found")

    if gym.get("plan") != "Pro" or not gym.get("pro_fee_paid"):
        return {"required": False}

    agreement = col_agreements.find_one({"gym_id": gym_id})
    return {"required": agreement is None, "signed": agreement is not None}


@app.get("/gym/{gym_id}/agreement")
def get_agreement(gym_id: str):
    doc = col_agreements.find_one({"gym_id": gym_id})
    if not doc:
        raise HTTPException(404, "No agreement on file for this gym")
    return _doc(doc)


@app.post("/gym/{gym_id}/agreement/submit")
def submit_agreement(gym_id: str, req: AgreementSubmit):
    gym = col_gyms.find_one({"gym_id": gym_id})
    if not gym:
        raise HTTPException(404, "Gym not found")
    if gym.get("plan") != "Pro" or not gym.get("pro_fee_paid"):
        raise HTTPException(400, "Pro Activation Fee must be paid before signing the agreement")
    if col_agreements.find_one({"gym_id": gym_id}):
        raise HTTPException(409, "An agreement has already been submitted for this gym")

    if not req.admin_name.strip() or not req.gym_name.strip() or not req.id_number.strip():
        raise HTTPException(400, "Admin name, gym name, and ID number are required")
    if req.id_type not in ("Aadhar", "Driving License", "Other"):
        raise HTTPException(400, "Invalid ID type")

    agreement_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    agreement_date = now.strftime("%d-%m-%Y")

    sig_url = upload_image(req.signature_base64, folder="aerofitdb/agreements/signatures", public_id=agreement_id)
    id_url  = upload_image(req.id_proof_base64,  folder="aerofitdb/agreements/id_proofs",  public_id=agreement_id)

    if not sig_url:
        raise HTTPException(400, "Signature image is required")
    if not id_url:
        raise HTTPException(400, "ID proof image is required")

    id_number_masked = _mask_id(req.id_number)

    sig_local_path = f"/tmp/sig_{agreement_id}.png"
    pdf_bytes = None
    try:
        resp = http_requests.get(sig_url, timeout=10)
        with open(sig_local_path, "wb") as f:
            f.write(resp.content)
        pdf_bytes = _generate_agreement_pdf(
            gym_name=req.gym_name.strip(),
            admin_name=req.admin_name.strip(),
            id_type=req.id_type,
            id_number_masked=id_number_masked,
            signature_local_path=sig_local_path,
            agreement_date=agreement_date,
        )
    finally:
        if os.path.exists(sig_local_path):
            os.remove(sig_local_path)

    pdf_upload = cloudinary.uploader.upload(
        pdf_bytes,
        resource_type="raw",
        folder="aerofitdb/agreements/pdf",
        public_id=agreement_id,
        format="pdf",
        overwrite=True,
    )
    pdf_url = pdf_upload.get("secure_url", "")

    doc = {
        "agreement_id":       agreement_id,
        "gym_id":             gym_id,
        "admin_name":         req.admin_name.strip(),
        "gym_name":           req.gym_name.strip(),
        "id_type":            req.id_type,
        "id_number_masked":   id_number_masked,
        "signature_url":      sig_url,
        "id_proof_url":       id_url,
        "agreement_pdf_url":  pdf_url,
        "pro_activation_fee": PRO_ACTIVATION_FEE_INR,
        "monthly_fee_per_user": AEROFIT_FEE_PER_USER,
        "agreement_date":     agreement_date,
        "status":             "signed",
        "created_at":         now,
    }
    col_agreements.insert_one(doc)

    print(f"✅  Agreement signed → gym={gym_id}  admin={req.admin_name}  pdf={pdf_url}", flush=True)
    return {
        "status":            "signed",
        "agreement_id":      agreement_id,
        "agreement_pdf_url": pdf_url,
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

AEROFIT_FEE_PER_USER = 35

@app.post("/alpha/invoices")
def create_invoice(req: InvoiceCreate):
    gym = col_gyms.find_one({"gym_id": req.gym_id})
    if not gym:
        raise HTTPException(404, "Gym not found")

    member_count = col_user_ids.count_documents({"gym_id": req.gym_id, "status": "used"})
    if member_count == 0:
        raise HTTPException(400, "This gym has no active members yet (no used User IDs)")

    auto_gross = round(AEROFIT_FEE_PER_USER * member_count, 2)
    gross      = round(req.gross_override, 2) if req.gross_override is not None else auto_gross

    invoice_id = str(uuid.uuid4())
    inv_number = _invoice_number()
    now        = datetime.now(timezone.utc)

    col_invoices.insert_one({
        "invoice_id":       invoice_id,
        "invoice_number":   inv_number,
        "gym_id":           req.gym_id,
        "gym_name":         gym["name"],
        "admin_email":      gym.get("admin_email", ""),
        "period":           req.period,
        "member_count":     member_count,
        "fee_per_user":     AEROFIT_FEE_PER_USER,
        "gross":            gross,
        "status":           "pending",
        "notes":            req.notes or "",
        "created_at":       now,
        "due_at":           now + timedelta(days=15),
        "paid_at":          None,
        "payment_ref":      None,
        "alerts":           [],
    })

    print(f"✅  Invoice {inv_number} created for {gym['name']} ({member_count} members × ₹{AEROFIT_FEE_PER_USER}) → ₹{gross}", flush=True)
    return {
        "status":         "created",
        "invoice_id":     invoice_id,
        "invoice_number": inv_number,
        "member_count":   member_count,
        "gross":          gross,
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
        "read":            False,
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

def _cleanup_old_billing_alerts(now: datetime) -> int:
    cutoff = now - timedelta(days=2)
    result = col_notifs.delete_many({
        "type":    "billing",
        "sent_at": {"$lte": cutoff},
    })
    if result.deleted_count:
        print(f"🧹  Cleaned up {result.deleted_count} billing alert(s) older than 2 days", flush=True)
    return result.deleted_count

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

    next_invoice_at = _ensure_utc(gym.get("billing_cycle_next_invoice_at"))
    next_billing_days_left = None
    if next_invoice_at:
        next_billing_days_left = max(0, (next_invoice_at - datetime.now(timezone.utc)).days)

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
        "next_billing_date":       _fmt_dt(next_invoice_at),
        "next_billing_days_left":  next_billing_days_left,
    }


@app.get("/gym/{gym_id}/notifications/unread-billing-count")
def gym_unread_billing_count(gym_id: str):
    if not col_gyms.find_one({"gym_id": gym_id}):
        raise HTTPException(404, "Gym not found")
    count = col_notifs.count_documents({
        "gym_id": gym_id,
        "type":   "billing",
        "read":   {"$ne": True},
    })
    return {"unread": count}


@app.post("/gym/{gym_id}/notifications/mark-billing-read")
def mark_billing_notifications_read(gym_id: str):
    if not col_gyms.find_one({"gym_id": gym_id}):
        raise HTTPException(404, "Gym not found")
    result = col_notifs.update_many(
        {"gym_id": gym_id, "type": "billing", "read": {"$ne": True}},
        {"$set": {"read": True, "read_at": datetime.now(timezone.utc)}},
    )
    return {"status": "ok", "updated": result.modified_count}

# ══════════════════════════════════════════════════════════════════════════════
#  Gym invoice payment — gym admin pays Aerofit directly via Razorpay
# ══════════════════════════════════════════════════════════════════════════════

@app.post("/gym/{gym_id}/invoices/{invoice_id}/create-payment-order")
def create_invoice_payment_order(gym_id: str, invoice_id: str):
    gym = col_gyms.find_one({"gym_id": gym_id})
    if not gym:
        raise HTTPException(404, "Gym not found")

    inv = col_invoices.find_one({"invoice_id": invoice_id, "gym_id": gym_id})
    if not inv:
        raise HTTPException(404, "Invoice not found for this gym")

    if inv.get("status") == "paid":
        raise HTTPException(400, "This invoice has already been paid")
    if inv.get("status") == "cancelled":
        raise HTTPException(400, "This invoice has been cancelled")

    existing_order_id = inv.get("razorpay_order_id")
    if existing_order_id:
        try:
            rp_order = razorpay_client.order.fetch(existing_order_id)
            if rp_order.get("status") == "created":
                return {
                    "order_id":      existing_order_id,
                    "key_id":        RAZORPAY_KEY_ID,
                    "amount":        rp_order["amount"],
                    "currency":      "INR",
                    "name":          "AERO-FIT",
                    "description":   f"Invoice {inv['invoice_number']} — {inv['period']}",
                    "prefill_email": gym.get("admin_email", ""),
                    "prefill_name":  gym.get("name", ""),
                    "invoice_number": inv["invoice_number"],
                }
        except Exception:
            pass

    amount_paise = int(round(inv["gross"] * 100))
    now = datetime.now(timezone.utc)

    try:
        rp_order = razorpay_client.order.create({
            "amount":   amount_paise,
            "currency": "INR",
            "receipt":  f"inv_{invoice_id[:16]}_{now.strftime('%m%d%H%M%S')}",
            "notes":    {
                "invoice_id":     invoice_id,
                "invoice_number": inv["invoice_number"],
                "gym_id":         gym_id,
            },
        })
    except Exception as e:
        print(f"❌  Razorpay invoice-order creation failed: {e}", flush=True)
        raise HTTPException(502, "Payment gateway error. Please try again.")

    order_id = rp_order["id"]
    col_invoices.update_one(
        {"invoice_id": invoice_id},
        {"$set": {"razorpay_order_id": order_id, "razorpay_order_created_at": now}},
    )

    print(f"✅  Invoice payment order created → {order_id}  invoice={inv['invoice_number']}  ₹{inv['gross']}", flush=True)
    return {
        "order_id":       order_id,
        "key_id":         RAZORPAY_KEY_ID,
        "amount":         amount_paise,
        "currency":       "INR",
        "name":           "AERO-FIT",
        "description":    f"Invoice {inv['invoice_number']} — {inv['period']}",
        "prefill_email":  gym.get("admin_email", ""),
        "prefill_name":   gym.get("name", ""),
        "invoice_number": inv["invoice_number"],
    }


@app.post("/gym/{gym_id}/invoices/{invoice_id}/verify-payment")
def verify_invoice_payment(gym_id: str, invoice_id: str, req: InvoicePaymentVerify):
    if not _verify_hmac(req.razorpay_order_id, req.razorpay_payment_id, req.razorpay_signature):
        raise HTTPException(400, "Payment verification failed. Signature mismatch.")

    inv = col_invoices.find_one({"invoice_id": invoice_id, "gym_id": gym_id})
    if not inv:
        raise HTTPException(404, "Invoice not found for this gym")

    if inv.get("status") == "paid":
        return {"status": "already_paid", "invoice_id": invoice_id}

    if inv.get("razorpay_order_id") != req.razorpay_order_id:
        raise HTTPException(400, "Order ID does not match this invoice")

    now = datetime.now(timezone.utc)
    col_invoices.update_one(
        {"invoice_id": invoice_id},
        {"$set": {
            "status":              "paid",
            "paid_at":             now,
            "payment_ref":         req.razorpay_payment_id,
            "payment_method":      "razorpay",
            "updated_at":          now,
        }},
    )

    col_gyms.update_one(
        {"gym_id": gym_id},
        {"$inc": {"revenue": inv.get("gym_amount", 0)}},
    )

    col_notifs.insert_one({
        "notification_id": str(uuid.uuid4()),
        "gym_id":          gym_id,
        "title":           f"✅ Payment Received — {inv['invoice_number']}",
        "body":            f"Your payment of ₹{inv['gross']:,.0f} for invoice {inv['invoice_number']} ({inv['period']}) was received via Razorpay. Thank you!",
        "type":            "billing",
        "segments":        ["admin"],
        "deep_link":       f"aerofit://billing/invoice/{invoice_id}",
        "scheduled_at":    "",
        "sent_at":         now,
        "invoice_id":      invoice_id,
        "read":            False,
    })

    print(f"✅  Invoice {inv['invoice_number']} paid via Razorpay → pid={req.razorpay_payment_id}", flush=True)
    return {
        "status":     "paid",
        "invoice_id": invoice_id,
        "paid_at":    now.isoformat(),
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
#  ROUTES — ALL MEMBERS (alpha admin — gym + indie unified view)
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/alpha/members")
def list_all_members():
    docs = list(col_users.find().sort("created_at", DESCENDING))

    gym_ids   = {d.get("gym_id") for d in docs if d.get("gym_id")}
    gym_names = {}
    if gym_ids:
        for g in col_gyms.find({"gym_id": {"$in": list(gym_ids)}}, {"gym_id": 1, "name": 1}):
            gym_names[g["gym_id"]] = g.get("name", "")

    emails_with_gym = [d["email"] for d in docs if d.get("gym_id")]
    uid_expiry: dict[str, str] = {}
    if emails_with_gym:
        for uid in col_user_ids.find(
            {"used_by": {"$in": emails_with_gym}, "status": "used"},
            {"used_by": 1, "expires_at": 1}
        ):
            uid_expiry[uid["used_by"]] = _fmt_dt(uid.get("expires_at"))

    result = []
    for d in docs:
        email      = d.get("email", "")
        weight     = d.get("weight_kg", 0)
        height_cm  = d.get("height_cm", 0)
        height_m   = height_cm / 100 if height_cm else 0
        bmi        = round(weight / (height_m ** 2), 1) if height_m > 0 else None

        gym_id     = d.get("gym_id")
        gym_name   = gym_names.get(gym_id, "") if gym_id else ""

        is_indie   = not gym_id

        if is_indie and d.get("indie_expires_at"):
            expires_at = _fmt_dt(d["indie_expires_at"])
        elif gym_id:
            expires_at = uid_expiry.get(email, "")
        else:
            expires_at = ""

        result.append({
            "email":              email,
            "name":               d.get("name", ""),
            "weight_kg":          weight,
            "height_cm":          height_cm,
            "bmi":                bmi,
            "gym_id":             gym_id,
            "gym_name":           gym_name,
            "member_type":        "indie" if is_indie else "gym",
            "plan_months":        d.get("plan_months", 1),
            "plan_label":         d.get("plan_label", "1 Month"),
            "membership_expired": d.get("membership_expired", False),
            "indie_expires_at":   _fmt_dt(d.get("indie_expires_at")) if is_indie else None,
            "expires_at":         expires_at,
            "created_at":         _fmt_dt(d.get("created_at")),
            "payment_platform":   d.get("payment_platform", "razorpay" if is_indie else ""),
        })

    return result

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

    now      = datetime.now(timezone.utc)
    is_indie = bool(user.get("indie_plan")) and not user.get("gym_id")
    expired_flag = bool(user.get("membership_expired", False))

    if expired_flag:
        if is_indie:
            grace_ends = _ensure_utc(user.get("grace_period_ends_at"))
            if not (grace_ends and grace_ends > now):
                raise HTTPException(403, "membership_expired")
        else:
            raise HTTPException(403, "membership_expired")

    if is_indie and user.get("indie_expires_at") and not expired_flag:
        indie_exp = _ensure_utc(user["indie_expires_at"])
        if indie_exp and indie_exp <= now:
            col_users.update_one(
                {"email": email},
                {"$set": {
                    "membership_expired":    True,
                    "membership_expired_at": now,
                    "grace_period_ends_at":  now + timedelta(days=2),
                }}
            )
            expired_flag = True

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
            "membership_expired": expired_flag,
            "membership_expires": membership_expires,
            "payment_platform":   user.get("payment_platform", ""),
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
        "payment_platform":   user.get("payment_platform", ""),
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

    now      = datetime.now(timezone.utc)
    is_indie = bool(user.get("indie_plan")) and not user.get("gym_id")

    if user.get("membership_expired"):
        if is_indie:
            grace_ends = _ensure_utc(user.get("grace_period_ends_at"))
            if grace_ends and grace_ends > now:
                return {
                    "valid":                 True,
                    "reason":                "grace_period",
                    "expired_at":            _fmt_dt(user.get("membership_expired_at")),
                    "grace_period_ends_at":  _fmt_dt(grace_ends),
                }
            return {
                "valid":      False,
                "reason":     "expired",
                "expired_at": _fmt_dt(user.get("membership_expired_at")),
            }
        return {
            "valid":      False,
            "reason":     "expired",
            "expired_at": _fmt_dt(user.get("membership_expired_at")),
        }

    if is_indie and user.get("indie_expires_at"):
        indie_exp = _ensure_utc(user["indie_expires_at"])
        if indie_exp and indie_exp <= now:
            grace_ends = now + timedelta(days=2)
            col_users.update_one(
                {"email": email},
                {"$set": {
                    "membership_expired":    True,
                    "membership_expired_at": now,
                    "grace_period_ends_at":  grace_ends,
                }}
            )
            return {
                "valid":                True,
                "reason":               "grace_period",
                "expired_at":           _fmt_dt(now),
                "grace_period_ends_at": _fmt_dt(grace_ends),
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
            return {"valid": False, "reason": "expired", "expired_at": _fmt_dt(expires_at)}
        return {"valid": True, "reason": "active", "expires_at": _fmt_dt(expires_at)}

    return {"valid": True, "reason": "active"}

@app.post("/user/{email}/delete-account")
def delete_own_account(email: str, req: DeleteAccountRequest):
    email = email.strip().lower()
    user = col_users.find_one({"email": email})
    if not user:
        raise HTTPException(404, "User not found")
    if not user.get("password") or not bcrypt.checkpw(
        req.password.encode(), user["password"].encode()
    ):
        raise HTTPException(401, "Incorrect password")

    gym_id = user.get("gym_id")
    if gym_id:
        uid_doc = col_user_ids.find_one({"used_by": email, "gym_id": gym_id})
        if uid_doc:
            col_user_ids.delete_one({"_id": uid_doc["_id"]})
            col_gyms.update_one(
                {"gym_id": gym_id, "members": {"$gt": 0}},
                {"$inc": {"members": -1}},
            )

    col_meals.delete_many({"email": email})
    col_scan_limits.delete_many({"email": email})
    col_indie_notifs.delete_many({"email": email})
    col_users.delete_one({"email": email})

    print(f"🗑️  Self-service account deletion → {email}", flush=True)
    return {"status": "deleted"}

@app.get("/indie/billing-status/{email}")
def indie_billing_status(email: str):
    email = email.strip().lower()
    user  = col_users.find_one({"email": email})
    if not user:
        raise HTTPException(404, "User not found")

    is_indie = bool(user.get("indie_plan")) and not user.get("gym_id")
    if not is_indie:
        return {"is_indie": False}

    expires_at = _ensure_utc(user.get("indie_expires_at"))
    grace_ends = _ensure_utc(user.get("grace_period_ends_at"))

    return {
        "is_indie":              True,
        "email":                 email,
        "plan_label":            user.get("plan_label", "1 Month"),
        "plan_months":           user.get("plan_months", 1),
        "indie_expires_at":      _fmt_dt(expires_at) if expires_at else None,
        "membership_expired":    user.get("membership_expired", False),
        "grace_period_ends_at":  _fmt_dt(grace_ends) if grace_ends else None,
        "payment_platform":      user.get("payment_platform", "razorpay"),
    }

# ══════════════════════════════════════════════════════════════════════════════
#  ROUTES — INDIE BILLING NOTIFICATIONS (in-app feed)
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/indie/notifications/{email}")
def get_indie_notifications(email: str):
    email = email.strip().lower()
    docs = list(
        col_indie_notifs.find({"email": email})
        .sort("sent_at", DESCENDING)
        .limit(20)
    )
    return [_doc(d) for d in docs]


@app.get("/indie/notifications/{email}/unread-count")
def get_indie_unread_count(email: str):
    email = email.strip().lower()
    count = col_indie_notifs.count_documents({"email": email, "read": False})
    return {"unread": count}


@app.post("/indie/notifications/{notification_id}/read")
def mark_indie_notification_read(notification_id: str):
    result = col_indie_notifs.update_one(
        {"notification_id": notification_id},
        {"$set": {"read": True, "read_at": datetime.now(timezone.utc)}},
    )
    if result.matched_count == 0:
        raise HTTPException(404, "Notification not found")
    return {"status": "ok"}


@app.post("/indie/notifications/{email}/read-all")
def mark_all_indie_notifications_read(email: str):
    email = email.strip().lower()
    result = col_indie_notifs.update_many(
        {"email": email, "read": False},
        {"$set": {"read": True, "read_at": datetime.now(timezone.utc)}},
    )
    return {"status": "ok", "updated": result.modified_count}

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
#  ROUTES — NOTIFICATIONS (with FCM push) — GYM ONLY
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

@app.get("/gym/{gym_id}/notifications/member")
def list_member_notifications(gym_id: str):
    if not col_gyms.find_one({"gym_id": gym_id}):
        raise HTTPException(404, "Gym not found")
    docs = list(
        col_notifs.find({
            "gym_id":   gym_id,
            "segments": {"$nin": ["admin"]},
        }).sort("sent_at", DESCENDING).limit(50)
    )
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
#  ROUTES — INDIE PLAN — ANDROID / RAZORPAY (independent users)
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/indie/pricing/{months}")
def indie_pricing(months: int):
    if months < 1 or months > 12:
        raise HTTPException(400, "months must be 1–12")
    return _indie_pricing(months)

@app.post("/indie/send-signup-otp")
def indie_send_signup_otp(req: IndieSendOtpRequest):
    email = req.email.strip().lower()
    if not re.match(r"^[\w\.-]+@[\w\.-]+\.\w{2,}$", email):
        raise HTTPException(400, "Invalid email address")
    if col_users.find_one({"email": email}):
        raise HTTPException(409, "An account with this email already exists")

    now = datetime.now(timezone.utc)
    otp = _generate_otp()

    col_signup_otps.delete_many({"email": email, "used": False})
    col_signup_otps.insert_one({
        "email":      email,
        "otp":        otp,
        "attempts":   0,
        "used":       False,
        "verified":   False,
        "created_at": now,
        "expires_at": now + timedelta(minutes=OTP_EXPIRY_MINUTES),
    })

    sent = _send_otp_email(email, "", otp)
    if not sent:
        print(f"⚠️  Signup OTP generated but email send failed for {email}", flush=True)

    print(f"✅  Signup OTP issued → {email}", flush=True)
    return {"status": "ok", "message": "OTP sent to your email."}


@app.post("/indie/verify-signup-otp")
def indie_verify_signup_otp(req: IndieVerifySignupOtpRequest):
    email = req.email.strip().lower()
    otp   = req.otp.strip()

    record = col_signup_otps.find_one({"email": email, "used": False})
    if not record:
        raise HTTPException(400, "No pending verification for this email. Please request a new OTP.")

    now = datetime.now(timezone.utc)
    if _ensure_utc(record["expires_at"]) <= now:
        col_signup_otps.delete_one({"_id": record["_id"]})
        raise HTTPException(400, "OTP has expired. Please request a new one.")

    if record.get("attempts", 0) >= OTP_MAX_ATTEMPTS:
        col_signup_otps.delete_one({"_id": record["_id"]})
        raise HTTPException(429, "Too many incorrect attempts. Please request a new OTP.")

    if record["otp"] != otp:
        col_signup_otps.update_one({"_id": record["_id"]}, {"$inc": {"attempts": 1}})
        remaining = OTP_MAX_ATTEMPTS - (record.get("attempts", 0) + 1)
        raise HTTPException(400, f"Incorrect OTP. {max(0, remaining)} attempt(s) remaining.")

    col_signup_otps.update_one({"_id": record["_id"]}, {"$set": {"verified": True, "used": True}})
    print(f"✅  Signup OTP verified → {email}", flush=True)
    return {"status": "ok"}


@app.post("/indie/create-order")
def indie_create_order(req: IndieOrderRequest):
    email = req.email.strip().lower()
    if not re.match(r"^[\w\.-]+@[\w\.-]+\.\w{2,}$", email):
        raise HTTPException(400, "Invalid email address")
    if col_users.find_one({"email": email}):
        raise HTTPException(409, "An account with this email already exists")

    otp_record = col_signup_otps.find_one({
        "email":    email,
        "verified": True,
        "used":     True,
    })
    if not otp_record:
        raise HTTPException(400, "Please verify your email with the OTP before proceeding to payment.")

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
        "payment_platform":   "razorpay",
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
            "payment_platform":   "razorpay",
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
        {
            "$set": {
                "indie_expires_at":   new_exp,
                "membership_expired": False,
                "plan_months":        months,
                "plan_label":         f"{months} Month{'s' if months > 1 else ''}",
                "payment_platform":   "razorpay",
            },
            "$unset": {
                "membership_expired_at": "",
                "grace_period_ends_at":  "",
            },
        }
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

    _create_indie_alert(
        email=email,
        alert_key=f"renewed_{req.razorpay_payment_id}",
        alert_type="renewed",
        title="✅ Plan renewed",
        body=f"Your AERO-FIT plan is now active until {new_exp.strftime('%d %b %Y')}.",
    )

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
#  ROUTES — INDIE PLAN — iOS / APPLE IN-APP PURCHASE (independent users)
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/indie/apple/pricing/{months}")
def indie_pricing_ios(months: int):
    if months < 1 or months > 12:
        raise HTTPException(400, "months must be 1–12")
    return _indie_pricing_ios(months)


@app.post("/indie/apple/prepare-signup")
def apple_prepare_signup(req: ApplePrepareSignupRequest):
    email = req.email.strip().lower()
    if not re.match(r"^[\w\.-]+@[\w\.-]+\.\w{2,}$", email):
        raise HTTPException(400, "Invalid email address")
    if col_users.find_one({"email": email}):
        raise HTTPException(409, "An account with this email already exists")

    now = datetime.now(timezone.utc)
    hashed_pw = bcrypt.hashpw(req.password.encode(), bcrypt.gensalt()).decode()

    col_apple_pending.update_one(
        {"email": email},
        {"$set": {
            "email": email,
            "name": req.name.strip(),
            "password": hashed_pw,
            "weight_kg": req.weight_kg,
            "height_cm": req.height_cm,
            "created_at": now,
            "expires_at": now + timedelta(hours=1),
        }},
        upsert=True,
    )
    print(f"✅  Apple pending signup stashed → {email}", flush=True)
    return {"status": "ok"}


@app.post("/indie/apple/verify-signup")
def apple_verify_signup(req: AppleVerifyRequest):
    email = req.email.strip().lower()

    pending = col_apple_pending.find_one({"email": email})
    if not pending:
        raise HTTPException(400, "No pending signup found for this email. Please start over.")
    if _ensure_utc(pending["expires_at"]) <= datetime.now(timezone.utc):
        col_apple_pending.delete_one({"email": email})
        raise HTTPException(400, "Signup session expired. Please start over.")
    if col_users.find_one({"email": email}):
        raise HTTPException(409, "Account already exists for this email")
    if col_apple_transactions.find_one({"transaction_id": req.transaction_id}):
        raise HTTPException(409, "This purchase has already been processed")

    months = APPLE_PRODUCT_MONTHS.get(req.product_id)
    if months is None:
        raise HTTPException(400, "Unknown product ID")

    receipt_json = _verify_apple_receipt(req.receipt_data)
    _find_apple_transaction(receipt_json, req.transaction_id, req.product_id)

    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(days=30 * months)
    pricing = _indie_pricing_ios(months)

    col_users.insert_one({
        "email": email,
        "name": pending["name"],
        "password": pending["password"],
        "weight_kg": pending["weight_kg"],
        "height_cm": pending["height_cm"],
        "gym_id": None,
        "plan_months": months,
        "plan_label": f"{months} Month{'s' if months > 1 else ''}",
        "indie_plan": True,
        "indie_expires_at": expires_at,
        "membership_expired": False,
        "created_at": now,
        "payment_platform": "apple",
    })
    col_apple_transactions.insert_one({
        "transaction_id": req.transaction_id,
        "product_id": req.product_id,
        "email": email,
        "type": "new",
        "amount_inr": pricing["final_inr"],
        "verified_at": now,
    })
    col_apple_pending.delete_one({"email": email})

    print(f"✅  Apple signup verified → {email}  {months}mo  ₹{pricing['final_inr']}  txn={req.transaction_id}", flush=True)
    return {
        "status": "ok",
        "user": {
            "email": email,
            "name": pending["name"],
            "weight_kg": pending["weight_kg"],
            "height_cm": pending["height_cm"],
            "gym_id": None,
            "gym_name": "",
            "indie_plan": True,
            "plan_months": months,
            "plan_label": f"{months} Month{'s' if months > 1 else ''}",
            "indie_expires_at": expires_at.isoformat(),
            "membership_expired": False,
            "membership_expires": expires_at.isoformat(),
            "payment_platform": "apple",
        },
    }


@app.post("/indie/apple/verify-renewal")
def apple_verify_renewal(req: AppleVerifyRequest):
    email = req.email.strip().lower()
    user = col_users.find_one({"email": email})
    if not user:
        raise HTTPException(404, "User not found")
    if not user.get("indie_plan"):
        raise HTTPException(400, "Only independent plan users can renew here")
    if col_apple_transactions.find_one({"transaction_id": req.transaction_id}):
        raise HTTPException(409, "This purchase has already been processed")

    months = APPLE_PRODUCT_MONTHS.get(req.product_id)
    if months is None:
        raise HTTPException(400, "Unknown product ID")

    receipt_json = _verify_apple_receipt(req.receipt_data)
    _find_apple_transaction(receipt_json, req.transaction_id, req.product_id)

    now = datetime.now(timezone.utc)
    current_exp = _ensure_utc(user.get("indie_expires_at"))
    base = current_exp if (current_exp and current_exp > now) else now
    new_exp = base + timedelta(days=30 * months)
    pricing = _indie_pricing_ios(months)

    col_users.update_one(
        {"email": email},
        {
            "$set": {
                "indie_expires_at": new_exp,
                "membership_expired": False,
                "plan_months": months,
                "plan_label": f"{months} Month{'s' if months > 1 else ''}",
                "payment_platform": "apple",
            },
            "$unset": {"membership_expired_at": "", "grace_period_ends_at": ""},
        },
    )
    col_apple_transactions.insert_one({
        "transaction_id": req.transaction_id,
        "product_id": req.product_id,
        "email": email,
        "type": "renewal",
        "amount_inr": pricing["final_inr"],
        "verified_at": now,
    })

    print(f"✅  Apple renewal verified → {email}  {months}mo  ₹{pricing['final_inr']}  new expiry: {new_exp.isoformat()}  txn={req.transaction_id}", flush=True)

    _create_indie_alert(
        email=email,
        alert_key=f"renewed_{req.transaction_id}",
        alert_type="renewed",
        title="✅ Plan renewed",
        body=f"Your AERO-FIT plan is now active until {new_exp.strftime('%d %b %Y')}.",
    )
    return {
        "status": "renewed",
        "email": email,
        "months": months,
        "new_expires_at": new_exp.isoformat(),
        "membership_expires": new_exp.isoformat(),
    }


@app.get("/indie/apple/payment-status/{transaction_id}")
def apple_payment_status(transaction_id: str):
    doc = col_apple_transactions.find_one({"transaction_id": transaction_id})
    if not doc:
        raise HTTPException(404, "Transaction not found")
    return {
        "transaction_id": transaction_id,
        "type":            doc.get("type"),
        "email":           doc.get("email"),
        "product_id":      doc.get("product_id"),
        "amount_inr":      doc.get("amount_inr"),
    }

# ══════════════════════════════════════════════════════════════════════════════
#  ROUTES — PASSWORD RESET (app users — /auth/*)
# ══════════════════════════════════════════════════════════════════════════════

@app.post("/auth/forgot-password")
def forgot_password(req: ForgotPasswordRequest):
    email = req.email.strip().lower()
    if not re.match(r"^[\w\.-]+@[\w\.-]+\.\w{2,}$", email):
        raise HTTPException(400, "Invalid email address")

    user = col_users.find_one({"email": email})
    generic_response = {
        "status":  "ok",
        "message": "If an account exists for this email, an OTP has been sent.",
    }

    if not user:
        print(f"ℹ️  Forgot-password requested for non-existent email: {email}", flush=True)
        return generic_response

    now = datetime.now(timezone.utc)
    otp = _generate_otp()

    col_password_resets.delete_many({"email": email, "used": False})
    col_password_resets.insert_one({
        "email":       email,
        "otp":         otp,
        "attempts":    0,
        "used":        False,
        "reset_token": None,
        "created_at":  now,
        "expires_at":  now + timedelta(minutes=OTP_EXPIRY_MINUTES),
    })

    sent = _send_otp_email(email, user.get("name", ""), otp)
    if not sent:
        print(f"⚠️  OTP generated but email send failed for {email}", flush=True)

    print(f"✅  OTP issued → {email}", flush=True)
    return generic_response


@app.post("/auth/verify-otp")
def verify_otp(req: VerifyOtpRequest):
    email = req.email.strip().lower()
    otp   = req.otp.strip()

    record = col_password_resets.find_one({"email": email, "used": False})
    if not record:
        raise HTTPException(400, "No pending reset request for this email. Please request a new OTP.")

    now = datetime.now(timezone.utc)
    if _ensure_utc(record["expires_at"]) <= now:
        col_password_resets.delete_one({"_id": record["_id"]})
        raise HTTPException(400, "OTP has expired. Please request a new one.")

    if record.get("attempts", 0) >= OTP_MAX_ATTEMPTS:
        col_password_resets.delete_one({"_id": record["_id"]})
        raise HTTPException(429, "Too many incorrect attempts. Please request a new OTP.")

    if record["otp"] != otp:
        col_password_resets.update_one(
            {"_id": record["_id"]},
            {"$inc": {"attempts": 1}},
        )
        remaining = OTP_MAX_ATTEMPTS - (record.get("attempts", 0) + 1)
        raise HTTPException(400, f"Incorrect OTP. {max(0, remaining)} attempt(s) remaining.")

    reset_token = _generate_reset_token()
    col_password_resets.update_one(
        {"_id": record["_id"]},
        {"$set": {
            "reset_token":        reset_token,
            "reset_token_expires": now + timedelta(minutes=RESET_TOKEN_EXPIRY_MINUTES),
        }},
    )

    print(f"✅  OTP verified → {email}", flush=True)
    return {"status": "ok", "reset_token": reset_token}


@app.post("/auth/reset-password")
def reset_password(req: ResetPasswordRequest):
    email = req.email.strip().lower()

    if len(req.new_password.strip()) < 6:
        raise HTTPException(400, "Password must be at least 6 characters")

    record = col_password_resets.find_one({
        "email":       email,
        "used":        False,
        "reset_token": req.reset_token,
    })
    if not record:
        raise HTTPException(400, "Invalid or expired reset session. Please start over.")

    now = datetime.now(timezone.utc)
    token_expiry = record.get("reset_token_expires")
    if not token_expiry or _ensure_utc(token_expiry) <= now:
        col_password_resets.delete_one({"_id": record["_id"]})
        raise HTTPException(400, "Reset session expired. Please start over.")

    user = col_users.find_one({"email": email})
    if not user:
        raise HTTPException(404, "User not found")

    hashed = bcrypt.hashpw(req.new_password.strip().encode(), bcrypt.gensalt()).decode()
    col_users.update_one({"email": email}, {"$set": {"password": hashed}})

    col_password_resets.update_one(
        {"_id": record["_id"]},
        {"$set": {"used": True, "used_at": now}},
    )

    print(f"✅  Password reset completed → {email}", flush=True)
    return {"status": "ok", "message": "Password reset successful. Please sign in."}


# ══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))