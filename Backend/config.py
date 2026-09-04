import os, sys
from dotenv import load_dotenv

load_dotenv()  # loads .env from the current working directory into os.environ

def _require(key: str) -> str:
    val = os.environ.get(key, "").strip()
    if not val:
        print(f"❌  FATAL: environment variable '{key}' is missing or empty", flush=True)
        sys.exit(1)
    return val

MONGO_URI          = _require("MONGO_URI")
CLOUDINARY_CLOUD   = _require("CLOUDINARY_CLOUD_NAME")
CLOUDINARY_API_KEY = _require("CLOUDINARY_API_KEY")
CLOUDINARY_SECRET  = _require("CLOUDINARY_API_SECRET")

FIREBASE_PROJECT_ID = os.environ.get("FIREBASE_PROJECT_ID", "").strip()
FIREBASE_CREDS_PATH = "/etc/secrets/firebase-service-account.json"

ALPHA_USERNAME = os.environ.get("ALPHA_USERNAME", "superadmin").strip()
ALPHA_PASSWORD = os.environ.get("ALPHA_PASSWORD", "aerofit_alpha_2025").strip()

RESEND_API_KEY = _require("RESEND_API_KEY")
RESEND_FROM    = os.environ.get("RESEND_FROM", "AERO-FIT <onboarding@resend.dev>").strip()

OTP_EXPIRY_MINUTES         = int(os.environ.get("OTP_EXPIRY_MINUTES", "10"))
OTP_MAX_ATTEMPTS           = int(os.environ.get("OTP_MAX_ATTEMPTS", "5"))
RESET_TOKEN_EXPIRY_MINUTES = int(os.environ.get("RESET_TOKEN_EXPIRY_MINUTES", "15"))

ALLOWED_ORIGINS = [
    "http://localhost:5173", "http://localhost:5174", "http://localhost:3000",
    "http://127.0.0.1:5173", "http://127.0.0.1:5174", "http://127.0.0.1:3000",
    "https://aryan212004.github.io",
    "https://myfittt.com",
    "https://www.myfittt.com",
]