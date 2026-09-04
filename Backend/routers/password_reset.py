import re, bcrypt
from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, HTTPException
from database import col_users, col_password_resets, col_gym_admins, col_gym_admin_resets
from models import (
    ForgotPasswordRequest, VerifyOtpRequest, ResetPasswordRequest,
    GymAdminForgotPasswordRequest, GymAdminVerifyOtpRequest, GymAdminResetPasswordRequest,
)
from utils import generate_otp, generate_reset_token, ensure_utc
from email_utils import send_otp_email
from config import OTP_EXPIRY_MINUTES, OTP_MAX_ATTEMPTS, RESET_TOKEN_EXPIRY_MINUTES

router = APIRouter(tags=["password_reset"])

# ── App users ─────────────────────────────────────────────────────────────

@router.post("/auth/forgot-password")
def forgot_password(req: ForgotPasswordRequest):
    email = req.email.strip().lower()
    if not re.match(r"^[\w\.-]+@[\w\.-]+\.\w{2,}$", email):
        raise HTTPException(400, "Invalid email address")

    user = col_users.find_one({"email": email})
    generic = {"status": "ok", "message": "If an account exists for this email, an OTP has been sent."}
    if not user:
        return generic

    now = datetime.now(timezone.utc)
    otp = generate_otp()
    col_password_resets.delete_many({"email": email, "used": False})
    col_password_resets.insert_one({
        "email": email, "otp": otp, "attempts": 0, "used": False, "reset_token": None,
        "created_at": now, "expires_at": now + timedelta(minutes=OTP_EXPIRY_MINUTES),
    })
    send_otp_email(email, user.get("name", ""), otp)
    print(f"✅  OTP issued → {email}", flush=True)
    return generic

@router.post("/auth/verify-otp")
def verify_otp(req: VerifyOtpRequest):
    email = req.email.strip().lower()
    otp = req.otp.strip()

    record = col_password_resets.find_one({"email": email, "used": False})
    if not record:
        raise HTTPException(400, "No pending reset request for this email. Please request a new OTP.")

    now = datetime.now(timezone.utc)
    if ensure_utc(record["expires_at"]) <= now:
        col_password_resets.delete_one({"_id": record["_id"]})
        raise HTTPException(400, "OTP has expired. Please request a new one.")
    if record.get("attempts", 0) >= OTP_MAX_ATTEMPTS:
        col_password_resets.delete_one({"_id": record["_id"]})
        raise HTTPException(429, "Too many incorrect attempts. Please request a new OTP.")
    if record["otp"] != otp:
        col_password_resets.update_one({"_id": record["_id"]}, {"$inc": {"attempts": 1}})
        remaining = OTP_MAX_ATTEMPTS - (record.get("attempts", 0) + 1)
        raise HTTPException(400, f"Incorrect OTP. {max(0, remaining)} attempt(s) remaining.")

    reset_token = generate_reset_token()
    col_password_resets.update_one(
        {"_id": record["_id"]},
        {"$set": {"reset_token": reset_token, "reset_token_expires": now + timedelta(minutes=RESET_TOKEN_EXPIRY_MINUTES)}},
    )
    return {"status": "ok", "reset_token": reset_token}

@router.post("/auth/reset-password")
def reset_password(req: ResetPasswordRequest):
    email = req.email.strip().lower()
    if len(req.new_password.strip()) < 6:
        raise HTTPException(400, "Password must be at least 6 characters")

    record = col_password_resets.find_one({"email": email, "used": False, "reset_token": req.reset_token})
    if not record:
        raise HTTPException(400, "Invalid or expired reset session. Please start over.")

    now = datetime.now(timezone.utc)
    token_expiry = record.get("reset_token_expires")
    if not token_expiry or ensure_utc(token_expiry) <= now:
        col_password_resets.delete_one({"_id": record["_id"]})
        raise HTTPException(400, "Reset session expired. Please start over.")

    user = col_users.find_one({"email": email})
    if not user:
        raise HTTPException(404, "User not found")

    hashed = bcrypt.hashpw(req.new_password.strip().encode(), bcrypt.gensalt()).decode()
    col_users.update_one({"email": email}, {"$set": {"password": hashed}})
    col_password_resets.update_one({"_id": record["_id"]}, {"$set": {"used": True, "used_at": now}})
    return {"status": "ok", "message": "Password reset successful. Please sign in."}

# ── Gym admins (website) ─────────────────────────────────────────────────

@router.post("/gym-admin/forgot-password")
def gym_admin_forgot_password(req: GymAdminForgotPasswordRequest):
    email = req.email.strip().lower()
    if not re.match(r"^[\w\.-]+@[\w\.-]+\.\w{2,}$", email):
        raise HTTPException(400, "Invalid email address")

    admin = col_gym_admins.find_one({"email": email})
    generic = {"status": "ok", "message": "If an admin account exists for this email, an OTP has been sent."}
    if not admin or admin.get("status") == "inactive":
        return generic

    now = datetime.now(timezone.utc)
    otp = generate_otp()
    col_gym_admin_resets.delete_many({"email": email, "used": False})
    col_gym_admin_resets.insert_one({
        "email": email, "otp": otp, "attempts": 0, "used": False, "reset_token": None,
        "created_at": now, "expires_at": now + timedelta(minutes=OTP_EXPIRY_MINUTES),
    })
    send_otp_email(email, admin.get("name", ""), otp)
    return generic

@router.post("/gym-admin/verify-otp")
def gym_admin_verify_otp(req: GymAdminVerifyOtpRequest):
    email = req.email.strip().lower()
    otp = req.otp.strip()

    record = col_gym_admin_resets.find_one({"email": email, "used": False})
    if not record:
        raise HTTPException(400, "No pending reset request for this email. Please request a new OTP.")

    now = datetime.now(timezone.utc)
    if ensure_utc(record["expires_at"]) <= now:
        col_gym_admin_resets.delete_one({"_id": record["_id"]})
        raise HTTPException(400, "OTP has expired. Please request a new one.")
    if record.get("attempts", 0) >= OTP_MAX_ATTEMPTS:
        col_gym_admin_resets.delete_one({"_id": record["_id"]})
        raise HTTPException(429, "Too many incorrect attempts. Please request a new OTP.")
    if record["otp"] != otp:
        col_gym_admin_resets.update_one({"_id": record["_id"]}, {"$inc": {"attempts": 1}})
        remaining = OTP_MAX_ATTEMPTS - (record.get("attempts", 0) + 1)
        raise HTTPException(400, f"Incorrect OTP. {max(0, remaining)} attempt(s) remaining.")

    reset_token = generate_reset_token()
    col_gym_admin_resets.update_one(
        {"_id": record["_id"]},
        {"$set": {"reset_token": reset_token, "reset_token_expires": now + timedelta(minutes=RESET_TOKEN_EXPIRY_MINUTES)}},
    )
    return {"status": "ok", "reset_token": reset_token}

@router.post("/gym-admin/reset-password")
def gym_admin_reset_password(req: GymAdminResetPasswordRequest):
    email = req.email.strip().lower()
    if len(req.new_password.strip()) < 6:
        raise HTTPException(400, "Password must be at least 6 characters")

    record = col_gym_admin_resets.find_one({"email": email, "used": False, "reset_token": req.reset_token})
    if not record:
        raise HTTPException(400, "Invalid or expired reset session. Please start over.")

    now = datetime.now(timezone.utc)
    token_expiry = record.get("reset_token_expires")
    if not token_expiry or ensure_utc(token_expiry) <= now:
        col_gym_admin_resets.delete_one({"_id": record["_id"]})
        raise HTTPException(400, "Reset session expired. Please start over.")

    admin = col_gym_admins.find_one({"email": email})
    if not admin:
        raise HTTPException(404, "Admin not found")

    hashed = bcrypt.hashpw(req.new_password.strip().encode(), bcrypt.gensalt()).decode()
    col_gym_admins.update_one({"email": email}, {"$set": {"password": hashed}})
    col_gym_admin_resets.update_one({"_id": record["_id"]}, {"$set": {"used": True, "used_at": now}})
    return {"status": "ok", "message": "Password reset successful. Please sign in."}