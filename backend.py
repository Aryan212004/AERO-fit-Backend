import os, sys, json, re, bcrypt, uuid, base64, traceback, threading, time
from datetime import datetime, timezone, timedelta
from typing import Optional
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

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
SCAN_LIMIT         = int(os.environ.get("SCAN_LIMIT", "10"))

ALPHA_USERNAME = os.environ.get("ALPHA_USERNAME", "superadmin").strip()
ALPHA_PASSWORD = os.environ.get("ALPHA_PASSWORD", "aerofit_alpha_2025").strip()

# ── Revenue split constants ───────────────────────────────────────────────────
PLATFORM_SHARE_PCT = 40   # % that goes to Aerofit platform
GYM_SHARE_PCT      = 60   # % that stays with gym admin

# ══════════════════════════════════════════════════════════════════════════════
#  MONGODB INIT
# ══════════════════════════════════════════════════════════════════════════════

from pymongo import MongoClient, DESCENDING
from pymongo.collection import Collection

_mongo_client: MongoClient = MongoClient(MONGO_URI)
_db_name = MONGO_URI.rsplit("/", 1)[-1].split("?")[0].strip() or "aerofitdb"
mdb = _mongo_client[_db_name]

# ── Collections ───────────────────────────────────────────────────────────────
col_users:       Collection = mdb["users"]
col_meals:       Collection = mdb["meals"]
col_banners:     Collection = mdb["banners"]
col_notifs:      Collection = mdb["notifications"]
col_scan_limits: Collection = mdb["scan_limits"]
col_gyms:        Collection = mdb["platform_gyms"]
col_gym_admins:  Collection = mdb["platform_gym_admins"]
col_user_ids:    Collection = mdb["gym_user_ids"]
col_invoices:    Collection = mdb["invoices"]

# ── Indexes ───────────────────────────────────────────────────────────────────
col_users.create_index("email", unique=True)
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
col_invoices.create_index([("gym_id", 1), ("created_at", DESCENDING)])
col_invoices.create_index("invoice_id", unique=True)
col_invoices.create_index("status")

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
#  KEEP-ALIVE THREAD
# ══════════════════════════════════════════════════════════════════════════════

def _keep_alive():
    time.sleep(60)
    while True:
        try:
            import requests as _req
            _req.get("https://aero-fit-backend.onrender.com/health", timeout=10)
            print("✅  Keep-alive ping sent", flush=True)
        except Exception as e:
            print(f"⚠️  Keep-alive failed: {e}", flush=True)
        time.sleep(300)

threading.Thread(target=_keep_alive, daemon=True).start()

# ══════════════════════════════════════════════════════════════════════════════
#  FASTAPI APP
# ══════════════════════════════════════════════════════════════════════════════

app = FastAPI(title="AERO-FIT API", version="13.0.0")

ALLOWED_ORIGINS = [
    "http://localhost:5173", "http://localhost:5174", "http://localhost:3000",
    "http://127.0.0.1:5173", "http://127.0.0.1:5174", "http://127.0.0.1:3000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins     = ALLOWED_ORIGINS,
    allow_credentials = False,
    allow_methods     = ["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
    allow_headers     = ["*"],
    expose_headers    = ["*"],
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

def _check_and_increment_scan_limit(email: str) -> int:
    today  = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    filter = {"email": email, "date": today}
    doc    = col_scan_limits.find_one(filter)
    if doc:
        count = doc.get("count", 0)
        if count >= SCAN_LIMIT:
            raise HTTPException(429, f"Daily scan limit reached ({SCAN_LIMIT}/day). Try again tomorrow!")
        col_scan_limits.update_one(filter, {"$inc": {"count": 1}})
        return SCAN_LIMIT - (count + 1)
    col_scan_limits.insert_one({**filter, "count": 1})
    return SCAN_LIMIT - 1

def _generate_code() -> str:
    chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    return "AF-" + "".join(__import__("random").choice(chars) for _ in range(4))

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

# ── Updated: plan_months field added (1–12) ───────────────────────────────────
class GenerateUserIdsRequest(BaseModel):
    count:       int = 1
    plan_months: int = 1   # 1–12 months validity granted on registration

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

# ══════════════════════════════════════════════════════════════════════════════
#  ROUTES — HEALTH
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/health")
def health():
    return {"status": "ok", "version": "13.0.0", "db": "mongodb", "ai": GEMINI_MDL_PRIMARY}

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
    gym = _doc(gym)
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

@app.delete("/alpha/gyms/{gym_id}")
def delete_gym(gym_id: str):
    if not col_gyms.find_one({"gym_id": gym_id}):
        raise HTTPException(404, "Gym not found")
    col_gyms.delete_one({"gym_id": gym_id})
    col_gym_admins.delete_one({"gym_id": gym_id})
    return {"status": "deleted", "gym_id": gym_id}

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
#  ROUTES — INVOICES  (super admin creates, gym admin views)
# ══════════════════════════════════════════════════════════════════════════════

@app.post("/alpha/invoices")
def create_invoice(req: InvoiceCreate):
    """Super admin generates invoice. Member count is auto-calculated from used User IDs."""
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
#  ROUTES — INVOICES (gym admin view — read-only)
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

    # Clamp values
    count       = max(1, min(req.count, 50))
    plan_months = max(1, min(req.plan_months, 12))
    plan_label  = f"{plan_months} Month{'s' if plan_months > 1 else ''}"

    codes = []
    now   = datetime.now(timezone.utc)

    for _ in range(count):
        for _attempt in range(10):
            code = _generate_code()
            if not col_user_ids.find_one({"code": code}):
                break
        col_user_ids.insert_one({
            "gym_id":      gym_id,
            "code":        code,
            "status":      "active",
            "plan_months": plan_months,   # ✅ stored at generation time
            "plan_label":  plan_label,    # ✅ human-readable label
            "created_at":  now,
            "used_at":     None,
            "used_by":     None,
            "expires_at":  None,          # ✅ set when a user actually registers
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
    # Return plan info so the mobile app can show what plan the user is getting
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

# ══════════════════════════════════════════════════════════════════════════════
#  ROUTES — USER MANAGEMENT
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

        # ✅ Pull plan_months from the User ID doc and calculate expiry
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
                "expires_at": expires_at,   # ✅ calculated from plan_months
            }},
        )
        col_gyms.update_one({"gym_id": gym_id}, {"$inc": {"members": 1}})

    hashed = bcrypt.hashpw(req.password.encode(), bcrypt.gensalt()).decode()
    col_users.insert_one({
        "email":        email,
        "name":         req.name.strip(),
        "password":     hashed,
        "weight_kg":    req.weight_kg,
        "height_cm":    req.height_cm,
        "gym_id":       req.gym_id or None,
        "plan_months":  plan_months,   # ✅ stored on user doc too
        "plan_label":   plan_label,
        "created_at":   datetime.now(timezone.utc),
    })
    return {"status": "created", "email": email, "plan_months": plan_months, "plan_label": plan_label}

@app.get("/admin/users")
def list_users():
    docs = list(col_users.find().sort("created_at", DESCENDING))
    return [
        {
            "email":       d["email"],
            "name":        d["name"],
            "weight_kg":   d["weight_kg"],
            "height_cm":   d["height_cm"],
            "gym_id":      d.get("gym_id"),
            "plan_months": d.get("plan_months", 1),
            "plan_label":  d.get("plan_label", "1 Month"),
            "created_at":  _fmt_dt(d.get("created_at")),
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
    gym_name = ""
    if user.get("gym_id"):
        gym = col_gyms.find_one({"gym_id": user["gym_id"]})
        if gym:
            gym_name = gym.get("name", "")

    # ✅ Fetch expires_at from the user's consumed User ID
    membership_expires = None
    if user.get("gym_id"):
        uid_doc = col_user_ids.find_one({"used_by": email, "gym_id": user["gym_id"]})
        if uid_doc and uid_doc.get("expires_at"):
            membership_expires = _fmt_dt(uid_doc["expires_at"])

    return {
        "status": "ok",
        "user": {
            "email":              user["email"],
            "name":               user["name"],
            "weight_kg":          user["weight_kg"],
            "height_cm":          user["height_cm"],
            "gym_id":             user.get("gym_id"),
            "gym_name":           gym_name,
            "plan_months":        user.get("plan_months", 1),
            "plan_label":         user.get("plan_label", "1 Month"),
            "membership_expires": membership_expires,  # ✅ ISO string or null
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

    return {
        "email":              user["email"],
        "name":               user["name"],
        "weight_kg":          user["weight_kg"],
        "height_cm":          user["height_cm"],
        "gym_id":             user.get("gym_id"),
        "gym_name":           gym_name,
        "plan_months":        user.get("plan_months", 1),
        "plan_label":         user.get("plan_label", "1 Month"),
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
    result = col_banners.delete_one({"banner_id": banner_id, "gym_id": gym_id})
    if result.deleted_count == 0:
        raise HTTPException(404, "Banner not found or belongs to a different gym")
    return {"status": "deleted"}

# ══════════════════════════════════════════════════════════════════════════════
#  ROUTES — NOTIFICATIONS
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
    return {"email": email.lower(), "used": used, "limit": SCAN_LIMIT, "remaining": max(0, SCAN_LIMIT - used)}

# ══════════════════════════════════════════════════════════════════════════════
#  ROUTES — MEALS
# ══════════════════════════════════════════════════════════════════════════════

@app.post("/analyze-meal")
def analyze_meal(req: MealRequest):
    try:
        remaining = 0
        if req.email:
            remaining = _check_and_increment_scan_limit(req.email.strip().lower())
        image_part = _b64_to_part(req.image_base64)
        prompt = (
            "Estimate nutrition for the EXACT portion shown. Return ONLY JSON:\n"
            '{"name":"","serving_size":"","kcal":0,"protein":0,"carbs":0,"fat":0,"fiber":0,"notes":""}'
        )
        text = _ask_gemini([image_part], prompt)
        d    = _extract_json(text)
        return {
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
    except HTTPException:
        raise
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(500, f"Analysis failed: {str(e)}")

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
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))