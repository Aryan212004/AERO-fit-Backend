import re, bcrypt
from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, HTTPException
from database import col_users, col_signup_otps
from models import IndieSendOtpRequest, IndieVerifySignupOtpRequest, AddUserRequest
from utils import generate_otp, ensure_utc
from email_utils import send_otp_email
from config import OTP_EXPIRY_MINUTES, OTP_MAX_ATTEMPTS

router = APIRouter(prefix="/indie", tags=["indie"])

@router.post("/send-signup-otp")
def send_signup_otp(req: IndieSendOtpRequest):
    email = req.email.strip().lower()
    if not re.match(r"^[\w\.-]+@[\w\.-]+\.\w{2,}$", email):
        raise HTTPException(400, "Invalid email address")
    if col_users.find_one({"email": email}):
        raise HTTPException(409, "An account with this email already exists")

    now = datetime.now(timezone.utc)
    otp = generate_otp()
    col_signup_otps.delete_many({"email": email, "used": False})
    col_signup_otps.insert_one({
        "email": email, "otp": otp, "attempts": 0, "used": False, "verified": False,
        "created_at": now, "expires_at": now + timedelta(minutes=OTP_EXPIRY_MINUTES),
    })
    send_otp_email(email, "", otp)
    print(f"✅  Signup OTP issued → {email}", flush=True)
    return {"status": "ok", "message": "OTP sent to your email."}

@router.post("/verify-signup-otp")
def verify_signup_otp(req: IndieVerifySignupOtpRequest):
    email = req.email.strip().lower()
    otp = req.otp.strip()
    record = col_signup_otps.find_one({"email": email, "used": False})
    if not record:
        raise HTTPException(400, "No pending verification for this email. Please request a new OTP.")

    now = datetime.now(timezone.utc)
    if ensure_utc(record["expires_at"]) <= now:
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

@router.post("/register")
def register(req: AddUserRequest):
    """Free independent-user signup — no payment, no plan expiry."""
    email = req.email.strip().lower()
    if not re.match(r"^[\w\.-]+@[\w\.-]+\.\w{2,}$", email):
        raise HTTPException(400, "Invalid email address")
    if col_users.find_one({"email": email}):
        raise HTTPException(409, "An account with this email already exists")

    otp_record = col_signup_otps.find_one({"email": email, "verified": True, "used": True})
    if not otp_record:
        raise HTTPException(400, "Please verify your email with the OTP before proceeding.")

    hashed = bcrypt.hashpw(req.password.encode(), bcrypt.gensalt()).decode()
    col_users.insert_one({
        "email": email, "name": req.name.strip(), "password": hashed,
        "weight_kg": req.weight_kg, "height_cm": req.height_cm,
        "gym_id": None, "plan_label": "Independent",
        "indie_plan": False, "membership_expired": False,
        "workout_plans_locked": True,
        "created_at": datetime.now(timezone.utc),
    })
    col_signup_otps.delete_many({"email": email})
    print(f"✅  Free indie account created → {email}", flush=True)
    return {"status": "created", "email": email}