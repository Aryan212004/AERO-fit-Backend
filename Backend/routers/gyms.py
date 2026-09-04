import re, uuid, bcrypt
from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, HTTPException
from pymongo import DESCENDING
from database import col_gyms, col_gym_admins, col_users, col_user_ids, col_banners, col_notifs, col_batches, col_trainers
from models import GymCreate, GymUpdate
from utils import doc

router = APIRouter(prefix="/alpha/gyms", tags=["gyms"])

def cascade_delete_gym(gym_id: str) -> dict:
    member_emails = [u["email"] for u in col_users.find({"gym_id": gym_id}, {"email": 1})]
    users_result = col_users.delete_many({"gym_id": gym_id})
    user_ids_result = col_user_ids.delete_many({"gym_id": gym_id})
    banners_result = col_banners.delete_many({"gym_id": gym_id})
    notifs_result = col_notifs.delete_many({"gym_id": gym_id})
    admins_result = col_gym_admins.delete_many({"gym_id": gym_id})
    batches_result = col_batches.delete_many({"gym_id": gym_id})
    col_trainers.delete_many({"gym_id": gym_id})
    col_gyms.delete_one({"gym_id": gym_id})

    summary = {
        "gym_id": gym_id,
        "users_deleted": users_result.deleted_count,
        "user_ids_deleted": user_ids_result.deleted_count,
        "banners_deleted": banners_result.deleted_count,
        "notifs_deleted": notifs_result.deleted_count,
        "admins_deleted": admins_result.deleted_count,
        "batches_deleted": batches_result.deleted_count,
    }
    print(f"🗑️  Cascade gym delete → {gym_id} | {summary}", flush=True)
    return summary

@router.get("")
def list_gyms():
    return [doc(d) for d in col_gyms.find().sort("created_at", DESCENDING)]

@router.post("")
def create_gym(req: GymCreate):
    admin_email = req.admin_email.strip().lower()
    if col_gym_admins.find_one({"email": admin_email}):
        raise HTTPException(409, "An admin with that email already exists")

    gym_id = "gym_" + str(uuid.uuid4())[:8]
    admin_id = "adm_" + str(uuid.uuid4())[:8]
    raw_pw = req.admin_password.strip() or re.sub(r"[^a-z0-9]", "", req.name.lower()) + "2025"
    now = datetime.now(timezone.utc)
    trial_expires_at = (now + timedelta(days=14)) if req.plan == "Trial" else None

    # Pro plan is free and instantly active — no activation fee anymore.
    col_gyms.insert_one({
        "gym_id": gym_id,
        "name": req.name.strip(),
        "city": req.city.strip(),
        "plan": req.plan,
        "status": "trial" if req.plan == "Trial" else "active",
        "members": 0,
        "admin_email": admin_email,
        "admin_id": admin_id,
        "trial_expires_at": trial_expires_at,
        "created_at": now,
    })

    hashed = bcrypt.hashpw(raw_pw.encode(), bcrypt.gensalt()).decode()
    col_gym_admins.insert_one({
        "admin_id": admin_id, "gym_id": gym_id, "gym_name": req.name.strip(),
        "name": req.admin_name.strip(), "email": admin_email,
        "password": hashed, "status": "active", "created_at": now,
    })

    print(f"✅  Gym created → {gym_id}  admin → {admin_email}", flush=True)
    return {
        "status": "created", "gym_id": gym_id, "admin_id": admin_id,
        "admin_email": admin_email, "admin_password": raw_pw,
    }

@router.get("/{gym_id}")
def get_gym(gym_id: str):
    gym = col_gyms.find_one({"gym_id": gym_id})
    if not gym:
        raise HTTPException(404, "Gym not found")
    gym = doc(gym)
    admin = col_gym_admins.find_one({"gym_id": gym_id})
    if admin:
        admin = doc(admin)
        admin.pop("password", None)
        gym["admin"] = admin
    return gym

@router.patch("/{gym_id}")
def update_gym(gym_id: str, req: GymUpdate):
    if not col_gyms.find_one({"gym_id": gym_id}):
        raise HTTPException(404, "Gym not found")
    update: dict = {"updated_at": datetime.now(timezone.utc)}
    if req.name is not None: update["name"] = req.name
    if req.city is not None: update["city"] = req.city
    if req.plan is not None: update["plan"] = req.plan
    if req.status is not None: update["status"] = req.status
    if req.members is not None: update["members"] = req.members
    col_gyms.update_one({"gym_id": gym_id}, {"$set": update})
    return {"status": "updated", "gym_id": gym_id}

@router.get("/{gym_id}/delete-preview")
def gym_delete_preview(gym_id: str):
    gym = col_gyms.find_one({"gym_id": gym_id})
    if not gym:
        raise HTTPException(404, "Gym not found")
    return {
        "gym_id": gym_id,
        "gym_name": gym.get("name", ""),
        "members": col_users.count_documents({"gym_id": gym_id}),
        "user_ids": col_user_ids.count_documents({"gym_id": gym_id}),
        "banners": col_banners.count_documents({"gym_id": gym_id}),
        "notifications": col_notifs.count_documents({"gym_id": gym_id}),
        "admins": col_gym_admins.count_documents({"gym_id": gym_id}),
    }

@router.delete("/{gym_id}")
def delete_gym(gym_id: str):
    if not col_gyms.find_one({"gym_id": gym_id}):
        raise HTTPException(404, "Gym not found")
    summary = cascade_delete_gym(gym_id)
    return {"status": "deleted", "gym_id": gym_id, "deleted": summary}