import os, sys, json, re, random, smtplib, bcrypt, uuid, base64, traceback
from datetime import datetime, timezone, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
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

GEMINI_API_KEY      = _require("GEMINI_API_KEY")
GMAIL_USER          = _require("GMAIL_USER")
GMAIL_APP_PASS      = _require("GMAIL_APP_PASS")
MONGO_URI           = _require("MONGO_URI")           # e.g. mongodb+srv://user:pass@cluster.mongodb.net/aerofitdb
CLOUDINARY_CLOUD    = _require("CLOUDINARY_CLOUD_NAME")
CLOUDINARY_API_KEY  = _require("CLOUDINARY_API_KEY")
CLOUDINARY_SECRET   = _require("CLOUDINARY_API_SECRET")
SCAN_LIMIT          = int(os.environ.get("SCAN_LIMIT", "10"))

# ══════════════════════════════════════════════════════════════════════════════
#  MONGODB INIT
# ══════════════════════════════════════════════════════════════════════════════

from pymongo import MongoClient, DESCENDING
from pymongo.collection import Collection

_mongo_client: MongoClient = MongoClient(MONGO_URI)

# Parse DB name from URI or fall back to "aerofitdb"
_db_name = MONGO_URI.rsplit("/", 1)[-1].split("?")[0].strip() or "aerofitdb"
mdb = _mongo_client[_db_name]

# Collections
col_users:       Collection = mdb["users"]
col_otps:        Collection = mdb["otps"]
col_meals:       Collection = mdb["meals"]
col_banners:     Collection = mdb["banners"]
col_notifs:      Collection = mdb["notifications"]
col_scan_limits: Collection = mdb["scan_limits"]

# Indexes (safe to call on every startup)
col_users.create_index("email",       unique=True)
col_otps.create_index("email",        unique=True)
col_otps.create_index("expires_at",   expireAfterSeconds=0)   # TTL index
col_meals.create_index([("email", 1), ("logged_at", DESCENDING)])
col_banners.create_index("created_at")
col_notifs.create_index("sent_at")
col_scan_limits.create_index([("email", 1), ("date", 1)], unique=True)

print(f"✅  MongoDB connected → {_db_name}", flush=True)

# ══════════════════════════════════════════════════════════════════════════════
#  CLOUDINARY INIT
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
#  GEMINI INIT
# ══════════════════════════════════════════════════════════════════════════════

from google import genai
from google.genai import types

gemini_client = genai.Client(api_key=GEMINI_API_KEY)
GEMINI_MDL    = "gemini-2.5-flash"
print(f"✅  Gemini ready → {GEMINI_MDL}", flush=True)

# ══════════════════════════════════════════════════════════════════════════════
#  FASTAPI APP
# ══════════════════════════════════════════════════════════════════════════════

app = FastAPI(title="AERO-FIT API", version="8.0.0")

ALLOWED_ORIGINS = [
    "http://localhost:5173",
    "http://localhost:5174",
    "http://localhost:3000",
    "http://127.0.0.1:5173",
    "http://127.0.0.1:5174",
    "http://127.0.0.1:3000",
    # "https://your-deployed-frontend.com",   # ← uncomment & fill in for prod
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
#  HELPERS — GENERAL
# ══════════════════════════════════════════════════════════════════════════════

def _strip_b64_prefix(b64: str) -> str:
    """Remove data-URI prefix if present."""
    return b64.split(",", 1)[1].strip() if "," in b64 else b64.strip()


def _b64_to_part(b64: str, mime: str = "image/jpeg") -> types.Part:
    if not b64:
        raise ValueError("Empty image data")
    return types.Part.from_bytes(data=base64.b64decode(_strip_b64_prefix(b64)), mime_type=mime)


def _ask_gemini(parts: list, prompt: str) -> str:
    all_parts = list(parts) + [types.Part.from_text(text=prompt)]
    response  = gemini_client.models.generate_content(
        model    = GEMINI_MDL,
        contents = [types.Content(role="user", parts=all_parts)],
    )
    return response.text


def _extract_json(text: str) -> dict:
    text = re.sub(r"```(?:json)?", "", text).strip()
    m    = re.search(r"\{.*\}", text, re.DOTALL)
    if not m:
        raise ValueError(f"No JSON found in Gemini response: {text[:300]}")
    return json.loads(m.group())


def _safe_int(val, default: int = 0) -> int:
    try:
        return int(float(str(val).replace("~", "").strip()))
    except Exception:
        return default


def _doc(d: dict) -> dict:
    """Strip MongoDB _id before returning to client."""
    d.pop("_id", None)
    return d

# ══════════════════════════════════════════════════════════════════════════════
#  HELPERS — CLOUDINARY IMAGE UPLOAD
# ══════════════════════════════════════════════════════════════════════════════

def upload_image(base64_str: str, folder: str, public_id: str = None) -> str:
    """
    Upload a base64 image to Cloudinary.
    Returns the secure HTTPS URL, or "" if base64_str is empty.
    """
    if not base64_str:
        return ""

    raw       = _strip_b64_prefix(base64_str)
    data_uri  = f"data:image/jpeg;base64,{raw}"          # Cloudinary accepts data URIs
    public_id = public_id or str(uuid.uuid4())

    result = cloudinary.uploader.upload(
        data_uri,
        folder            = folder,
        public_id         = public_id,
        overwrite         = True,
        resource_type     = "image",
        format            = "jpg",
        transformation    = [{"quality": "auto", "fetch_format": "auto"}],
    )
    url = result.get("secure_url", "")
    print(f"✅  Cloudinary upload → {url}", flush=True)
    return url

# ══════════════════════════════════════════════════════════════════════════════
#  HELPERS — SCAN LIMIT
# ══════════════════════════════════════════════════════════════════════════════

def _check_and_increment_scan_limit(email: str) -> int:
    today  = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    filter = {"email": email, "date": today}
    doc    = col_scan_limits.find_one(filter)

    if doc:
        count = doc.get("count", 0)
        if count >= SCAN_LIMIT:
            raise HTTPException(
                429,
                f"Daily scan limit reached ({SCAN_LIMIT}/day). Try again tomorrow! 🔄",
            )
        col_scan_limits.update_one(filter, {"$inc": {"count": 1}})
        return SCAN_LIMIT - (count + 1)
    else:
        col_scan_limits.insert_one({**filter, "count": 1})
        return SCAN_LIMIT - 1

# ══════════════════════════════════════════════════════════════════════════════
#  HELPERS — EMAIL / OTP
# ══════════════════════════════════════════════════════════════════════════════

def send_otp_email(to_email: str, otp: str) -> bool:
    try:
        msg            = MIMEMultipart("alternative")
        msg["Subject"] = f"🔐 {otp} is your AERO-FIT code"
        msg["From"]    = f"AERO-FIT <{GMAIL_USER}>"
        msg["To"]      = to_email
        msg.attach(MIMEText(f"Your AERO-FIT code: {otp}", "plain"))
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as s:
            s.login(GMAIL_USER, GMAIL_APP_PASS)
            s.sendmail(GMAIL_USER, to_email, msg.as_string())
        print(f"✅  OTP sent to {to_email}", flush=True)
        return True
    except Exception as e:
        print(f"❌  Email failed: {e}  —  OTP: {otp}", flush=True)
        return False

# ══════════════════════════════════════════════════════════════════════════════
#  PYDANTIC MODELS
# ══════════════════════════════════════════════════════════════════════════════

class OtpRequest(BaseModel):
    email: str

class OtpVerifyRequest(BaseModel):
    email: str
    otp:   str

class UserProfile(BaseModel):
    email:     str
    name:      str
    weight_kg: float
    height_cm: float

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

class NotificationCreate(BaseModel):
    title:        str
    body:         str
    type:         str        = "general"
    segments:     list[str]  = ["all"]
    deep_link:    Optional[str] = None
    scheduled_at: Optional[str] = None

# ══════════════════════════════════════════════════════════════════════════════
#  ROUTES — HEALTH
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/health")
def health():
    return {"status": "ok", "version": "8.0.0", "db": "mongodb", "ai": GEMINI_MDL}

# ══════════════════════════════════════════════════════════════════════════════
#  ROUTES — BANNERS
# ══════════════════════════════════════════════════════════════════════════════

@app.post("/banners")
def create_banner(req: BannerCreate):
    banner_id = str(uuid.uuid4())
    image_url = upload_image(req.image_base64 or "", folder="aerofitdb/banners", public_id=banner_id)

    doc = {
        "banner_id":  banner_id,
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


@app.get("/banners")
def list_banners(screen: str = None):
    query = {"screen": screen} if screen else {}
    docs  = list(col_banners.find(query).sort("created_at", DESCENDING))
    return [_doc(d) for d in docs]


@app.delete("/banners/{banner_id}")
def delete_banner(banner_id: str):
    result = col_banners.delete_one({"banner_id": banner_id})
    if result.deleted_count == 0:
        raise HTTPException(404, "Banner not found")
    return {"status": "deleted"}

# ══════════════════════════════════════════════════════════════════════════════
#  ROUTES — NOTIFICATIONS
# ══════════════════════════════════════════════════════════════════════════════

@app.post("/notifications")
def create_notification(req: NotificationCreate):
    notif_id = str(uuid.uuid4())
    doc = {
        "notification_id": notif_id,
        "title":           req.title,
        "body":            req.body,
        "type":            req.type,
        "segments":        req.segments,
        "deep_link":       req.deep_link    or "",
        "scheduled_at":    req.scheduled_at or "",
        "sent_at":         datetime.now(timezone.utc),
    }
    col_notifs.insert_one(doc)
    return {"status": "sent", "notification_id": notif_id}


@app.get("/notifications")
def list_notifications():
    docs = list(col_notifs.find().sort("sent_at", DESCENDING).limit(50))
    return [_doc(d) for d in docs]

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
#  ROUTES — OTP
# ══════════════════════════════════════════════════════════════════════════════

@app.post("/send-otp")
def send_otp(req: OtpRequest):
    email = req.email.strip().lower()
    if not re.match(r"^[\w\.-]+@[\w\.-]+\.\w{2,}$", email):
        raise HTTPException(400, "Invalid email")

    otp      = str(random.randint(100000, 999999))
    otp_hash = bcrypt.hashpw(otp.encode(), bcrypt.gensalt()).decode()
    expires  = datetime.now(timezone.utc) + timedelta(minutes=10)

    col_otps.replace_one(
        {"email": email},
        {
            "email":      email,
            "otp_hash":   otp_hash,
            "expires_at": expires,           # TTL index will auto-delete expired docs
            "used":       False,
            "attempts":   0,
        },
        upsert=True,
    )

    return {
        "status":     "sent",
        "email":      email,
        "email_sent": send_otp_email(email, otp),
        "expires_in": 600,
    }


@app.post("/verify-otp")
def verify_otp(req: OtpVerifyRequest):
    email  = req.email.strip().lower()
    record = col_otps.find_one({"email": email})

    if not record:
        raise HTTPException(400, "No active OTP")
    if record.get("used"):
        raise HTTPException(400, "OTP already used")

    expires_at = record["expires_at"]
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if datetime.now(timezone.utc) > expires_at:
        col_otps.delete_one({"email": email})
        raise HTTPException(400, "Code expired")

    attempts = record.get("attempts", 0)
    if attempts >= 5:
        col_otps.delete_one({"email": email})
        raise HTTPException(400, "Too many attempts")

    if not bcrypt.checkpw(req.otp.strip().encode(), record["otp_hash"].encode()):
        col_otps.update_one({"email": email}, {"$inc": {"attempts": 1}})
        raise HTTPException(400, f"Incorrect code. {4 - attempts} left.")

    col_otps.update_one({"email": email}, {"$set": {"used": True}})

    user = col_users.find_one({"email": email})
    if user:
        return {
            "status": "verified",
            "is_new": False,
            "user": {
                "email":     user["email"],
                "name":      user["name"],
                "weight_kg": user["weight_kg"],
                "height_cm": user["height_cm"],
            },
        }

    return {"status": "verified", "is_new": True, "user": None}

# ══════════════════════════════════════════════════════════════════════════════
#  ROUTES — USER PROFILE
# ══════════════════════════════════════════════════════════════════════════════

@app.post("/save-profile")
def save_profile(req: UserProfile):
    email = req.email.strip().lower()
    col_users.update_one(
        {"email": email},
        {"$set": {
            "email":      email,
            "name":       req.name.strip(),
            "weight_kg":  req.weight_kg,
            "height_cm":  req.height_cm,
            "updated_at": datetime.now(timezone.utc),
        }},
        upsert=True,
    )
    return {"status": "saved", "email": email}


@app.get("/user/{email}")
def get_user(email: str):
    user = col_users.find_one({"email": email.lower()})
    if not user:
        raise HTTPException(404, "User not found")
    return {
        "email":     user["email"],
        "name":      user["name"],
        "weight_kg": user["weight_kg"],
        "height_cm": user["height_cm"],
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
        raise HTTPException(500, str(e))


@app.post("/log-meal")
def log_meal(req: LogMealRequest):
    try:
        meal_id   = str(uuid.uuid4())
        image_url = upload_image(
            req.image_base64 or "",
            folder    = f"aerofitdb/meals/{req.email.lower()}",
            public_id = meal_id,
        )
        doc = {
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
        }
        col_meals.insert_one(doc)
        print(f"✅  Meal logged → {meal_id}", flush=True)
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
        col_meals.find(
            {"email": email.lower(), "logged_at": {"$gte": since}}
        ).sort("logged_at", DESCENDING)
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