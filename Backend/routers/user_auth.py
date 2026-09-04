import bcrypt
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException
from database import col_users, col_gyms, col_user_ids
from models import UserLogin, UserUpdate, DeleteAccountRequest, FcmTokenUpdate
from utils import fmt_dt, ensure_utc

router = APIRouter(tags=["user_auth"])

@router.post("/user/login")
def user_login(req: UserLogin):
    email = req.email.strip().lower()
    user = col_users.find_one({"email": email})
    if not user or not user.get("password"):
        raise HTTPException(401, "Invalid email or password")
    if not bcrypt.checkpw(req.password.encode(), user["password"].encode()):
        raise HTTPException(401, "Invalid email or password")

    now = datetime.now(timezone.utc)
    expired_flag = bool(user.get("membership_expired", False))

    if expired_flag and user.get("gym_id"):
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
            if ensure_utc(uid_doc["expires_at"]) <= now:
                col_users.update_one(
                    {"email": email},
                    {"$set": {"membership_expired": True, "membership_expired_at": now, "gym_id": None}},
                )
                raise HTTPException(403, "membership_expired")
            membership_expires = fmt_dt(uid_doc["expires_at"])

    return {
        "status": "ok",
        "user": {
            "email": user["email"], "name": user["name"],
            "weight_kg": user["weight_kg"], "height_cm": user["height_cm"],
            "gym_id": user.get("gym_id"), "gym_name": gym_name,
            "indie_plan": user.get("indie_plan", False),
            "plan_months": user.get("plan_months", 1),
            "plan_label": user.get("plan_label", "Independent" if not user.get("gym_id") else "1 Month"),
            "membership_expired": expired_flag,
            "membership_expires": membership_expires,
        },
    }

@router.get("/user/{email}")
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
            membership_expires = fmt_dt(uid_doc["expires_at"])

    return {
        "email": user["email"], "name": user["name"],
        "weight_kg": user["weight_kg"], "height_cm": user["height_cm"],
        "gym_id": user.get("gym_id"), "gym_name": gym_name,
        "indie_plan": user.get("indie_plan", False),
        "plan_months": user.get("plan_months", 1),
        "plan_label": user.get("plan_label", "1 Month"),
        "membership_expired": user.get("membership_expired", False),
        "membership_expires": membership_expires,
    }

@router.put("/user/{email}")
def update_user(email: str, req: UserUpdate):
    email = email.lower()
    if not col_users.find_one({"email": email}):
        raise HTTPException(404, "User not found")
    update: dict = {"updated_at": datetime.now(timezone.utc)}
    if req.name is not None: update["name"] = req.name
    if req.weight_kg is not None: update["weight_kg"] = req.weight_kg
    if req.height_cm is not None: update["height_cm"] = req.height_cm
    col_users.update_one({"email": email}, {"$set": update})
    return {"status": "updated"}

@router.post("/user/{email}/fcm-token")
def update_fcm_token(email: str, req: FcmTokenUpdate):
    col_users.update_one(
        {"email": email.lower()},
        {"$set": {"fcm_token": req.fcm_token, "updated_at": datetime.now(timezone.utc)}},
    )
    return {"status": "ok"}

@router.get("/user/{email}/membership-status")
def membership_status(email: str):
    email = email.strip().lower()
    user = col_users.find_one({"email": email})
    if not user:
        raise HTTPException(404, "User not found")

    now = datetime.now(timezone.utc)

    if user.get("membership_expired") and user.get("gym_id"):
        return {"valid": False, "reason": "expired", "expired_at": fmt_dt(user.get("membership_expired_at"))}

    if not user.get("gym_id"):
        return {"valid": True, "reason": "no_gym"}

    uid_doc = col_user_ids.find_one({"used_by": email, "gym_id": user["gym_id"]})
    if uid_doc:
        expires_at = uid_doc.get("expires_at")
        if expires_at and ensure_utc(expires_at) <= now:
            col_users.update_one(
                {"email": email},
                {"$set": {"membership_expired": True, "membership_expired_at": now, "gym_id": None}},
            )
            return {"valid": False, "reason": "expired", "expired_at": fmt_dt(expires_at)}
        return {"valid": True, "reason": "active", "expires_at": fmt_dt(expires_at)}

    return {"valid": True, "reason": "active"}

@router.post("/user/{email}/delete-account")
def delete_own_account(email: str, req: DeleteAccountRequest):
    email = email.strip().lower()
    user = col_users.find_one({"email": email})
    if not user:
        raise HTTPException(404, "User not found")
    if not user.get("password") or not bcrypt.checkpw(req.password.encode(), user["password"].encode()):
        raise HTTPException(401, "Incorrect password")

    gym_id = user.get("gym_id")
    if gym_id:
        uid_doc = col_user_ids.find_one({"used_by": email, "gym_id": gym_id})
        if uid_doc:
            col_user_ids.delete_one({"_id": uid_doc["_id"]})
            col_gyms.update_one({"gym_id": gym_id, "members": {"$gt": 0}}, {"$inc": {"members": -1}})

    col_users.delete_one({"email": email})
    print(f"🗑️  Self-service account deletion → {email}", flush=True)
    return {"status": "deleted"}