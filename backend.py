import os, sys, json, re, random, smtplib, bcrypt, uuid, base64, traceback
from datetime import datetime, timezone, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# ── Load .env for local dev (no-op on Render) ─────────────────────────────────
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# ══════════════════════════════════════════════════════════════════════════════
#  CONFIG  — validate all required env vars at startup so Render logs show
#            exactly which variable is missing instead of a cryptic traceback
# ══════════════════════════════════════════════════════════════════════════════

def _require(key: str) -> str:
    val = os.environ.get(key, "").strip()
    if not val:
        print(f"❌  FATAL: environment variable '{key}' is missing or empty", flush=True)
        sys.exit(1)
    return val

GEMINI_API_KEY  = _require("GEMINI_API_KEY")
GMAIL_USER      = _require("GMAIL_USER")
GMAIL_APP_PASS  = _require("GMAIL_APP_PASS")
FIREBASE_BUCKET = os.environ.get("FIREBASE_BUCKET", "aero-fit.firebasestorage.app")
SCAN_LIMIT      = int(os.environ.get("SCAN_LIMIT", "10"))

# ══════════════════════════════════════════════════════════════════════════════
#  FIREBASE INIT
#  Local  → reads JSON key file from ~/Downloads/
#  Render → reads individual env vars (set each field separately)
# ══════════════════════════════════════════════════════════════════════════════

import firebase_admin
from firebase_admin import credentials, firestore, storage

_KEY_FILE = os.path.expanduser(
    "~/Downloads/aero-fit-firebase-adminsdk-fbsvc-cdd5ade0cb.json"
)

if os.path.exists(_KEY_FILE):
    # ── LOCAL dev ─────────────────────────────────────────────────────────────
    cred = credentials.Certificate(_KEY_FILE)
    print("🔑  Local Firebase JSON key loaded", flush=True)
else:
    # ── PRODUCTION (Render) ───────────────────────────────────────────────────
    # Paste the full private key into the Render env var.
    # Render preserves literal newlines — do NOT escape as \n.
    # If you accidentally pasted \n escapes, this block fixes them:
    private_key = _require("FIREBASE_PRIVATE_KEY")
    if "\\n" in private_key and "\n" not in private_key:
        private_key = private_key.replace("\\n", "\n")

    FIREBASE_CREDS = {
        "type":                        "service_account",
        "project_id":                  _require("FIREBASE_PROJECT_ID"),
        "private_key_id":              _require("FIREBASE_PRIVATE_KEY_ID"),
        "private_key":                 private_key,
        "client_email":                _require("FIREBASE_CLIENT_EMAIL"),
        "client_id":                   _require("FIREBASE_CLIENT_ID"),
        "auth_uri":                    "https://accounts.google.com/o/oauth2/auth",
        "token_uri":                   "https://oauth2.googleapis.com/token",
        "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
        "client_x509_cert_url":        _require("FIREBASE_CLIENT_CERT_URL"),
        "universe_domain":             "googleapis.com",
    }
    cred = credentials.Certificate(FIREBASE_CREDS)
    print("🔑  Render env var Firebase credentials loaded", flush=True)

firebase_admin.initialize_app(cred, {"storageBucket": FIREBASE_BUCKET})
db     = firestore.client()
bucket = storage.bucket()
print("✅  Firebase connected", flush=True)

# ══════════════════════════════════════════════════════════════════════════════
#  GEMINI INIT
# ══════════════════════════════════════════════════════════════════════════════

from google import genai
from google.genai import types

client     = genai.Client(api_key=GEMINI_API_KEY)
GEMINI_MDL = "gemini-2.5-flash"
print(f"✅  Gemini ready → {GEMINI_MDL}", flush=True)

# ══════════════════════════════════════════════════════════════════════════════
#  FASTAPI APP
# ══════════════════════════════════════════════════════════════════════════════

app = FastAPI(title="AERO-FIT API", version="7.1.0")

# Allow all origins — CORS must be the FIRST middleware added
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,        # must be False when allow_origins=["*"]
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
)

# ══════════════════════════════════════════════════════════════════════════════
#  HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def _b64_to_part(b64: str, mime: str = "image/jpeg") -> types.Part:
    if not b64:
        raise ValueError("Empty image data")
    if "," in b64:
        b64 = b64.split(",", 1)[1]
    b64 = b64.strip()
    return types.Part.from_bytes(data=base64.b64decode(b64), mime_type=mime)


def _ask_gemini(parts: list, prompt: str) -> str:
    all_parts = list(parts) + [types.Part.from_text(text=prompt)]
    response  = client.models.generate_content(
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


def _check_and_increment_scan_limit(email: str) -> int:
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    ref   = db.collection("scan_limits").document(f"{email}_{today}")
    doc   = ref.get()
    if doc.exists:
        count = doc.to_dict().get("count", 0)
        if count >= SCAN_LIMIT:
            raise HTTPException(
                429,
                f"Daily scan limit reached ({SCAN_LIMIT}/day). Try again tomorrow! 🔄"
            )
        ref.update({"count": count + 1})
        return SCAN_LIMIT - (count + 1)
    else:
        ref.set({"email": email, "date": today, "count": 1})
        return SCAN_LIMIT - 1


def upload_image(base64_str: str, folder: str, filename: str = None) -> str:
    if not base64_str:
        return ""
    if "," in base64_str:
        base64_str = base64_str.split(",", 1)[1]
    base64_str  = base64_str.strip()
    image_bytes = base64.b64decode(base64_str)
    filename    = filename or f"{uuid.uuid4()}.jpg"
    blob_path   = f"{folder}/{filename}"
    blob        = bucket.blob(blob_path)

    download_token = str(uuid.uuid4())
    blob.metadata  = {"firebaseStorageDownloadTokens": download_token}
    blob.upload_from_string(image_bytes, content_type="image/jpeg")

    encoded_path = blob_path.replace("/", "%2F")
    url = (
        f"https://firebasestorage.googleapis.com/v0/b/{FIREBASE_BUCKET}"
        f"/o/{encoded_path}?alt=media&token={download_token}"
    )
    print(f"✅  Uploaded → {url}", flush=True)
    return url


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
    screen:       str          = "home"
    status:       str          = "active"
    expires_at:   Optional[str] = None
    deep_link:    Optional[str] = None
    image_base64: Optional[str] = None

class NotificationCreate(BaseModel):
    title:        str
    body:         str
    type:         str          = "general"
    segments:     list[str]    = ["all"]
    deep_link:    Optional[str] = None
    scheduled_at: Optional[str] = None


# ══════════════════════════════════════════════════════════════════════════════
#  ROUTES — HEALTH  (used as Render health-check path)
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/health")
def health():
    return {"status": "ok", "version": "7.1.0", "db": "firebase", "ai": GEMINI_MDL}


# ══════════════════════════════════════════════════════════════════════════════
#  ROUTES — BANNERS
# ══════════════════════════════════════════════════════════════════════════════

@app.post("/banners")
def create_banner(req: BannerCreate):
    banner_id = str(uuid.uuid4())
    image_url = ""
    if req.image_base64:
        image_url = upload_image(
            req.image_base64,
            folder   = "banners",
            filename = f"{banner_id}.jpg",
        )
    db.collection("banners").document(banner_id).set({
        "title":      req.title,
        "screen":     req.screen,
        "status":     req.status,
        "expires_at": req.expires_at or "",
        "deep_link":  req.deep_link  or "",
        "image_url":  image_url,
        "created_at": datetime.now(timezone.utc),
    })
    return {"status": "created", "banner_id": banner_id, "image_url": image_url}


@app.get("/banners")
def list_banners(screen: str = None):
    docs = db.collection("banners").stream()
    banners = [{"id": d.id, **d.to_dict()} for d in docs]
    
    # Filter and sort in Python instead of Firestore query
    if screen:
        banners = [b for b in banners if b.get("screen") == screen]
    
    # Sort by created_at descending in Python
    def sort_key(b):
        ca = b.get("created_at")
        if ca is None:
            return 0
        if hasattr(ca, "timestamp"):   # Firestore Timestamp
            return ca.timestamp()
        return 0
    
    banners.sort(key=sort_key, reverse=True)
    return banners


@app.delete("/banners/{banner_id}")
def delete_banner(banner_id: str):
    db.collection("banners").document(banner_id).delete()
    return {"status": "deleted"}


# ══════════════════════════════════════════════════════════════════════════════
#  ROUTES — NOTIFICATIONS
# ══════════════════════════════════════════════════════════════════════════════

@app.post("/notifications")
def create_notification(req: NotificationCreate):
    notif_id = str(uuid.uuid4())
    db.collection("notifications").document(notif_id).set({
        "title":        req.title,
        "body":         req.body,
        "type":         req.type,
        "segments":     req.segments,
        "deep_link":    req.deep_link    or "",
        "scheduled_at": req.scheduled_at or "",
        "sent_at":      datetime.now(timezone.utc),
    })
    return {"status": "sent", "notification_id": notif_id}


@app.get("/notifications")
def list_notifications():
    docs = db.collection("notifications").order_by(
        "sent_at", direction=firestore.Query.DESCENDING
    ).limit(50).stream()
    return [{"id": d.id, **d.to_dict()} for d in docs]


# ══════════════════════════════════════════════════════════════════════════════
#  ROUTES — SCAN LIMIT
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/scan-limit/{email}")
def get_scan_limit(email: str):
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    doc   = db.collection("scan_limits").document(f"{email.lower()}_{today}").get()
    used  = doc.to_dict().get("count", 0) if doc.exists else 0
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

    db.collection("otps").document(email).set({
        "otp_hash":   otp_hash,
        "expires_at": datetime.now(timezone.utc) + timedelta(minutes=10),
        "used":       False,
        "attempts":   0,
    })

    return {
        "status":     "sent",
        "email":      email,
        "email_sent": send_otp_email(email, otp),
        "expires_in": 600,
    }


@app.post("/verify-otp")
def verify_otp(req: OtpVerifyRequest):
    email = req.email.strip().lower()
    doc   = db.collection("otps").document(email).get()

    if not doc.exists:
        raise HTTPException(400, "No active OTP")

    record = doc.to_dict()

    if record.get("used"):
        raise HTTPException(400, "OTP already used")

    expires_at = record["expires_at"]
    if hasattr(expires_at, "replace"):
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if datetime.now(timezone.utc) > expires_at:
        db.collection("otps").document(email).delete()
        raise HTTPException(400, "Code expired")

    attempts = record.get("attempts", 0)
    if attempts >= 5:
        db.collection("otps").document(email).delete()
        raise HTTPException(400, "Too many attempts")

    if not bcrypt.checkpw(req.otp.strip().encode(), record["otp_hash"].encode()):
        db.collection("otps").document(email).update({"attempts": attempts + 1})
        raise HTTPException(400, f"Incorrect code. {4 - attempts} left.")

    db.collection("otps").document(email).update({"used": True})

    user_doc = db.collection("users").document(email).get()
    if user_doc.exists:
        u = user_doc.to_dict()
        return {
            "status": "verified",
            "is_new": False,
            "user": {
                "email":     u["email"],
                "name":      u["name"],
                "weight_kg": u["weight_kg"],
                "height_cm": u["height_cm"],
            },
        }

    return {"status": "verified", "is_new": True, "user": None}


# ══════════════════════════════════════════════════════════════════════════════
#  ROUTES — USER PROFILE
# ══════════════════════════════════════════════════════════════════════════════

@app.post("/save-profile")
def save_profile(req: UserProfile):
    email = req.email.strip().lower()
    db.collection("users").document(email).set(
        {
            "email":      email,
            "name":       req.name.strip(),
            "weight_kg":  req.weight_kg,
            "height_cm":  req.height_cm,
            "updated_at": datetime.now(timezone.utc),
        },
        merge=True,
    )
    return {"status": "saved", "email": email}


@app.get("/user/{email}")
def get_user(email: str):
    doc = db.collection("users").document(email.lower()).get()
    if not doc.exists:
        raise HTTPException(404, "User not found")
    u = doc.to_dict()
    return {
        "email":     u["email"],
        "name":      u["name"],
        "weight_kg": u["weight_kg"],
        "height_cm": u["height_cm"],
    }


@app.put("/user/{email}")
def update_user(email: str, req: UserUpdate):
    ref = db.collection("users").document(email.lower())
    if not ref.get().exists:
        raise HTTPException(404, "User not found")

    update: dict = {"updated_at": datetime.now(timezone.utc)}
    if req.name      is not None: update["name"]      = req.name
    if req.weight_kg is not None: update["weight_kg"] = req.weight_kg
    if req.height_cm is not None: update["height_cm"] = req.height_cm

    ref.update(update)
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
            folder   = f"meals/{req.email.lower()}",
            filename = f"{meal_id}.jpg",
        )
        db.collection("meals").document(meal_id).set({
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
    docs  = (
        db.collection("meals")
          .where("email",     "==", email.lower())
          .where("logged_at", ">=", since)
          .stream()
    )
    meals = [{"id": d.id, **d.to_dict()} for d in docs]
    
    # Sort in Python instead
    def sort_key(m):
        la = m.get("logged_at")
        if la is None: return 0
        if hasattr(la, "timestamp"): return la.timestamp()
        return 0
    
    meals.sort(key=sort_key, reverse=True)
    return meals


@app.delete("/meal/{meal_id}")
def delete_meal(meal_id: str):
    ref = db.collection("meals").document(meal_id)
    if not ref.get().exists:
        raise HTTPException(404, "Meal not found")
    ref.delete()
    return {"status": "deleted"}


# ══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))