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
PRO_ACTIVATION_FEE_INR = float(os.environ.get("PRO_ACTIVATION_FEE_INR", "5000"))  # ₹/year

INDIE_BASE_PRICE   = float(os.environ.get("INDIE_BASE_PRICE",  "159"))  # ₹/month — Android/Razorpay
INDIE_DISCOUNT_PCT = float(os.environ.get("INDIE_DISCOUNT_PCT", "1"))   # 1% per extra month — Android/Razorpay

# ── iOS / Apple In-App Purchase pricing ──────────────────────────────────────
# Apple's App Store pricing is flat per-month with NO multi-month discount —
# this must match exactly what's configured for each product in App Store
# Connect (aerofit_indie_1m/3m/6m/12m), since Apple owns the actual charge.
# This backend constant is only used to (a) display pricing before purchase
# and (b) sanity-check receipts; it never creates a Razorpay order.
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
    """
    iOS / Apple IAP pricing — flat ₹199/month, NO multi-month discount.
    e.g. 1mo = ₹199, 3mo = ₹597, 6mo = ₹1194, 12mo = ₹2388.
    Must mirror what's configured for each product in App Store Connect —
    this is used for display/estimate only; Apple owns the actual charge.
    """
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
    """
    Validates a StoreKit receipt against Apple's verifyReceipt endpoint.
    Tries production first; if Apple returns status 21007 ("this receipt
    is from the test environment"), retries against sandbox — Apple's
    documented pattern, so TestFlight/dev builds and real purchases both
    work without branching client-side.
    """
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
    """
    Finds the specific transaction in a verified receipt and cross-checks
    product_id against what Apple recorded — never trust the client's
    claimed product_id alone.
    """
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
#  CASCADE INDIE-USER DELETE HELPER
# ══════════════════════════════════════════════════════════════════════════════

def _cascade_delete_indie_user(email: str) -> dict:
    """
    Permanently deletes an independent (non-gym) user who failed to renew
    within the 2-day grace period after their plan expired.
    Deletes: user record, meal logs, scan-limit records, and any indie
    billing-alert notifications for this email.
    Payment history is intentionally kept for accounting purposes.
    Gym members are NEVER passed to this function.
    """
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
#  FCM PUSH SENDER (indie — direct device-token based)
# ══════════════════════════════════════════════════════════════════════════════

def _send_fcm_push_to_token(token: str, title: str, body: str, data: dict = {}):
    """
    Sends an OS-level push notification to a single device by FCM token.
    Used for independent (non-gym) users who aren't subscribed to any
    gym_{id} topic. Mirrors _send_fcm_push but targets `token` not `topic`.
    """
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
    """
    Creates an in-app indie notification AND fires a direct device push,
    but only ONCE per (email, alert_key) — alert_key acts as a dedupe
    fingerprint (e.g. "expiring_soon_2026-06-25" or "grace_period_2026-06-22")
    so the hourly job never spams the same alert twice.

    Returns True if a new alert was created, False if it already existed
    (i.e. already sent — safe to call every hour without duplicating).
    """
    now = datetime.now(timezone.utc)
    try:
        col_indie_notifs.insert_one({
            "notification_id": str(uuid.uuid4()),
            "email":            email,
            "alert_key":        alert_key,
            "alert_type":       alert_type,   # "expiring_soon" | "grace_period" | "renewed"
            "title":            title,
            "body":             body,
            "deep_link":        deep_link,
            "read":             False,
            "sent_at":          now,
        })
    except Exception:
        # Duplicate key on (email, alert_key) — already sent this exact alert.
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
    """
    Sends the OTP email via Resend. Returns True on success.
    Swap this function's body if you switch email providers later —
    nothing else in the codebase needs to change.
    """
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
    """Pings the server every 5 min to prevent Render free-tier sleep."""
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
    """
    Hourly job — now FOUR tasks:
      1. Expire gym memberships whose user-ID expires_at has passed.
      2a. Raise a "renew soon" billing alert (in-app + push) for indie
          users whose plan expires within the next 3 days.
      2b. Move indie users whose indie_expires_at has passed into a
          2-day grace period, AND raise a "grace period" billing alert
          (in-app + push) the moment that happens.
      2c. Permanently delete indie users whose grace period has lapsed.

    Gym members are NEVER auto-deleted — only indie accounts, and only
    after they fail to renew within the 2-day grace window.
    """
    time.sleep(30)
    while True:
        try:
            now = datetime.now(timezone.utc)

            # ── 0. Billing alerts older than 2 days → permanent delete ─────────
            _cleanup_old_billing_alerts(now)

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

            # ── 2a. Indie plans expiring within 3 days → "renew soon" alert ────
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

            # ── 2b. Indie plan expirations → enter 2-day grace period ──────────
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

            # ── 1b. Trial gyms past their 14-day window → auto-delete ──────────
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

            # ── 2c. Indie users past grace period → permanent deletion ─────────
            # Gym members are NEVER auto-deleted — only indie accounts.
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


threading.Thread(target=_keep_alive,     daemon=True).start()
threading.Thread(target=_run_expiry_job, daemon=True).start()
print("✅  Background threads started (keep-alive + expiry job)", flush=True)

# ══════════════════════════════════════════════════════════════════════════════
#  FASTAPI APP
# ══════════════════════════════════════════════════════════════════════════════

app = FastAPI(title="AERO-FIT API", version="20.0.0")

ALLOWED_ORIGINS = [
    "http://localhost:5173", "http://localhost:5174", "http://localhost:3000",
    "http://127.0.0.1:5173", "http://127.0.0.1:5174", "http://127.0.0.1:3000",
    "https://aryan212004.github.io",
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

# ══════════════════════════════════════════════════════════════════════════════
#  ROUTES — HEALTH
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/health")
def health():
    return {
        "status":         "ok",
        "version":        "20.0.0",
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
#  ROUTES — PRO PLAN ACTIVATION (₹5,000/year — required before a Pro gym's
#  admin can access the dashboard; checked on every login, no bypass)
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
            "expiring_soon": days_left <= 15,   # ← new
        }

    return {
        "required": True,
        "amount":   PRO_ACTIVATION_FEE_INR,
        "expired":  bool(paid and expires_at and expires_at <= now),
    }


@app.post("/gym/{gym_id}/pro-activation/create-order")
def pro_activation_create_order(gym_id: str):
    """
    Creates a Razorpay order for the fixed ₹5,000/year fee. Reuses an
    existing unpaid order if one is still open, same pattern as invoice
    payment orders, so repeated "Pay" clicks don't spam Razorpay.
    """
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
            pass  # fall through and create a fresh order below

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


@app.post("/gym/{gym_id}/pro-activation/verify-payment")
def pro_activation_verify_payment(gym_id: str, req: ProActivationVerify):
    """
    Verifies the Razorpay payment signature server-side, then unlocks the
    dashboard for exactly 1 year. If the admin is renewing before expiry,
    the extra year stacks on top of the current expiry (same pattern as
    indie plan renewals) rather than resetting from "now".
    """
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

    col_gyms.update_one(
        {"gym_id": gym_id},
        {"$set": {
            "pro_fee_paid":             True,
            "pro_fee_paid_at":          now,
            "pro_fee_expires_at":       new_expiry,
            "pro_fee_last_payment_ref": req.razorpay_payment_id,
        }},
    )

    print(f"✅  Pro activation paid → gym={gym_id}  pid={req.razorpay_payment_id}  valid until {new_expiry.isoformat()}", flush=True)
    return {
        "status":     "activated",
        "gym_id":     gym_id,
        "expires_at": new_expiry.isoformat(),
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

AEROFIT_FEE_PER_USER = 40

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
    """
    Deletes billing-alert notifications (the ones super admin sends to gym
    admins via /alpha/invoices/{id}/alert) once they're older than 2 days.
    These are stored in col_notifs with type == "billing". Gym members
    never see these (they're filtered out by the /member endpoint), so
    this only affects what shows in the gym admin's Billing tab.
    """
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


@app.get("/gym/{gym_id}/notifications/unread-billing-count")
def gym_unread_billing_count(gym_id: str):
    """
    Lightweight count for the sidebar Billing badge's "unread alerts" half.
    Docs created before the `read` field existed are treated as unread
    (missing read == not yet seen), so nothing old silently disappears.
    """
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
    """
    Called once when the gym admin opens the Billing tab — marks every
    billing notification for this gym as read so the "unread alerts" half
    of the sidebar badge clears. The "pending invoices" half of the badge
    is untouched here; that only drops when an invoice is actually paid.
    """
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
    """
    Gym admin clicks "Pay Now" on a pending invoice → this creates a
    Razorpay order for the EXACT invoice.gross amount (never trusts a
    client-supplied amount) and returns checkout details for the
    Razorpay widget on the frontend.
    """
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

    # Reuse an existing pending Razorpay order for this invoice if one was
    # already created (e.g. admin opened checkout, closed it, clicked again) —
    # avoids creating duplicate orders on the Razorpay side.
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
            pass  # fall through and create a fresh order below

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
    """
    Verifies the Razorpay payment signature server-side (never trusts the
    frontend's word that payment succeeded), then marks the invoice paid,
    credits gym revenue, and raises a receipt notification — mirroring
    exactly what /alpha/invoices/{id}/status does when super admin marks
    an invoice paid manually, so both paths stay consistent.
    """
    if not _verify_hmac(req.razorpay_order_id, req.razorpay_payment_id, req.razorpay_signature):
        raise HTTPException(400, "Payment verification failed. Signature mismatch.")

    inv = col_invoices.find_one({"invoice_id": invoice_id, "gym_id": gym_id})
    if not inv:
        raise HTTPException(404, "Invoice not found for this gym")

    if inv.get("status") == "paid":
        # Already processed (e.g. duplicate webhook/retry) — idempotent success.
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
    """
    Returns every user in the platform — gym members and indie users —
    with membership type, gym name, expiry, and BMI enriched inline.
    """
    docs = list(col_users.find().sort("created_at", DESCENDING))

    # Build a gym_id → gym_name lookup in one shot
    gym_ids   = {d.get("gym_id") for d in docs if d.get("gym_id")}
    gym_names = {}
    if gym_ids:
        for g in col_gyms.find({"gym_id": {"$in": list(gym_ids)}}, {"gym_id": 1, "name": 1}):
            gym_names[g["gym_id"]] = g.get("name", "")

    # Build email → expires_at lookup for gym members from col_user_ids
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

        # ── member_type is derived from gym_id, NOT the indie_plan flag ──────
        # gym_id presence is the ground truth: a user with no gym is indie,
        # regardless of whether indie_plan was ever correctly set on legacy
        # records (e.g. older /admin/add-user signups before the Razorpay
        # indie flow existed).
        is_indie   = not gym_id

        # Determine expiry
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
            # else: still inside the 2-day grace period — let them log in
            # so they can reach the Billing card and renew.
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
            # don't raise — grace period just started, allow this login through

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
                # Still inside the 2-day grace window — keep the app usable
                # so the user can reach the Billing card and renew.
                return {
                    "valid":                 True,
                    "reason":                "grace_period",
                    "expired_at":            _fmt_dt(user.get("membership_expired_at")),
                    "grace_period_ends_at":  _fmt_dt(grace_ends),
                }
            # Grace period over — should already be deleted by the
            # background job; this is just a fail-safe.
            return {
                "valid":      False,
                "reason":     "expired",
                "expired_at": _fmt_dt(user.get("membership_expired_at")),
            }
        # Gym members — unchanged original behaviour.
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
    """
    Self-service account deletion (Apple Guideline 5.1.1(v)). Requires the
    user's current password so a stolen session token alone can't wipe an
    account. Gym members have their User ID slot released back to the gym
    instead of deleting the gym's data; indie users are fully removed.
    """
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
    """
    Lightweight billing summary for the Profile → Billing card.
    Returns is_indie:false for gym members (frontend hides the card).
    """
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
    """
    Returns the indie billing-alert feed for one user, newest first.
    Frontend calls this on Profile screen open (and/or polls it) to render
    in-app banners and an unread badge. Always scoped by email — indie
    users have no gym_id to key off of, unlike the gym notification feed.
    """
    email = email.strip().lower()
    docs = list(
        col_indie_notifs.find({"email": email})
        .sort("sent_at", DESCENDING)
        .limit(20)
    )
    return [_doc(d) for d in docs]


@app.get("/indie/notifications/{email}/unread-count")
def get_indie_unread_count(email: str):
    """Lightweight count for a notification-bell badge."""
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
    """Convenience bulk endpoint — call when the user opens the alert feed."""
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

@app.get("/gym/{gym_id}/notifications/member")
def list_member_notifications(gym_id: str):
    """
    Member-facing feed — excludes notifications tagged for admin-only
    segments (e.g. billing alerts), so members never see invoice/payment
    reminders meant for the gym owner.
    """
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
    """Android pricing — ₹159/month base, with multi-month discount."""
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

    # Mark verified — create-order will check this flag before allowing payment
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

    # ── Require a verified OTP before allowing payment ──────────────────────
    otp_record = col_signup_otps.find_one({
        "email":    email,
        "verified": True,
        "used":     True,
    })
    if not otp_record:
        raise HTTPException(400, "Please verify your email with the OTP before proceeding to payment.")
    # ─────────────────────────────────────────────────────────────────────

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
#  Pricing: flat ₹199/month, NO multi-month discount (matches App Store
#  Connect product prices for aerofit_indie_1m/3m/6m/12m). Android keeps
#  its separate ₹159/month + discount pricing via /indie/pricing/{months}.
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/indie/apple/pricing/{months}")
def indie_pricing_ios(months: int):
    """iOS display pricing — ₹199/month flat, e.g. 3mo = ₹597, 12mo = ₹2388."""
    if months < 1 or months > 12:
        raise HTTPException(400, "months must be 1–12")
    return _indie_pricing_ios(months)


@app.post("/indie/apple/prepare-signup")
def apple_prepare_signup(req: ApplePrepareSignupRequest):
    """
    Step 1 of iOS signup: stash the account form data before the StoreKit
    purchase sheet opens. Apple's receipt only proves what was bought, not
    who's signing up, so we park name/password/weight/height here first.
    """
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
    """
    Step 2: called once StoreKit reports 'purchased'/'restored'. Verifies
    the receipt with Apple, dedupes on transaction_id, then creates the
    account from the data stashed in prepare-signup. Plan months are
    derived from the verified product_id — never trusted from the client
    beyond what Apple's receipt confirms.
    """
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
    """
    Verifies the receipt, dedupes on transaction_id, extends
    indie_expires_at — same stacking logic as the Razorpay renewal path.
    """
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
#  ROUTES — PASSWORD RESET
# ══════════════════════════════════════════════════════════════════════════════

@app.post("/auth/forgot-password")
def forgot_password(req: ForgotPasswordRequest):
    email = req.email.strip().lower()
    if not re.match(r"^[\w\.-]+@[\w\.-]+\.\w{2,}$", email):
        raise HTTPException(400, "Invalid email address")

    user = col_users.find_one({"email": email})
    # Deliberately vague response either way, so attackers can't use this
    # endpoint to discover which emails are registered.
    generic_response = {
        "status":  "ok",
        "message": "If an account exists for this email, an OTP has been sent.",
    }

    if not user:
        print(f"ℹ️  Forgot-password requested for non-existent email: {email}", flush=True)
        return generic_response

    now = datetime.now(timezone.utc)
    otp = _generate_otp()

    # Replace any previous unused OTP for this email with a fresh one.
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
        # Don't leak delivery failures to the client — log server-side only.
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

    # OTP correct — issue a short-lived reset token so the client doesn't
    # need to keep resubmitting the OTP on the next screen.
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

    # Mark this reset record used (don't delete immediately — keeps an audit trail)
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