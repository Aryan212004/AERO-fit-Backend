import re, uuid, bcrypt
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException
from pymongo import DESCENDING
from database import col_gym_admins, col_gyms
from models import GymAdminUpdate
from utils import doc

router = APIRouter(prefix="/alpha/admins", tags=["admins"])

@router.get("")
def list_gym_admins():
    result = []
    for d in col_gym_admins.find().sort("created_at", DESCENDING):
        d = doc(d)
        d.pop("password", None)
        result.append(d)
    return result

@router.post("/{gym_id}")
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
    raw_pw = re.sub(r"[^a-z0-9]", "", gym["name"].lower()) + "2025"
    hashed = bcrypt.hashpw(raw_pw.encode(), bcrypt.gensalt()).decode()
    col_gym_admins.insert_one({
        "admin_id": admin_id, "gym_id": gym_id, "gym_name": gym["name"],
        "name": (req.name or "Admin").strip(), "email": email,
        "password": hashed, "status": "active", "created_at": datetime.now(timezone.utc),
    })
    return {"status": "created", "admin_id": admin_id, "admin_email": email, "admin_password": raw_pw}

@router.patch("/{admin_id}")
def update_gym_admin(admin_id: str, req: GymAdminUpdate):
    if not col_gym_admins.find_one({"admin_id": admin_id}):
        raise HTTPException(404, "Admin not found")
    update: dict = {"updated_at": datetime.now(timezone.utc)}
    if req.name is not None: update["name"] = req.name
    if req.email is not None: update["email"] = req.email.strip().lower()
    if req.status is not None: update["status"] = req.status
    col_gym_admins.update_one({"admin_id": admin_id}, {"$set": update})
    return {"status": "updated", "admin_id": admin_id}

@router.delete("/{admin_id}")
def delete_gym_admin(admin_id: str):
    result = col_gym_admins.delete_one({"admin_id": admin_id})
    if result.deleted_count == 0:
        raise HTTPException(404, "Admin not found")
    return {"status": "deleted", "admin_id": admin_id}