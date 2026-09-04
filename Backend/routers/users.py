import re, bcrypt
from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, HTTPException
from pymongo import DESCENDING
from database import col_users, col_user_ids, col_gyms
from models import AddUserRequest
from utils import fmt_dt

router = APIRouter(tags=["users_admin"])

@router.post("/admin/add-user")
def add_user(req: AddUserRequest):
    email = req.email.strip().lower()
    if not re.match(r"^[\w\.-]+@[\w\.-]+\.\w{2,}$", email):
        raise HTTPException(400, "Invalid email address")
    if col_users.find_one({"email": email}):
        raise HTTPException(409, "User already exists")

    plan_months = 1
    plan_label = "1 Month"

    if req.gym_id and req.user_id:
        gym_id = req.gym_id.strip()
        code = req.user_id.strip().upper()
        d = col_user_ids.find_one({"gym_id": gym_id, "code": code})
        if not d:
            raise HTTPException(400, "Invalid User ID for this gym")
        if d.get("status") != "active":
            raise HTTPException(400, "This User ID has already been used")

        plan_months = d.get("plan_months", 1)
        plan_label = d.get("plan_label", f"{plan_months} Month{'s' if plan_months > 1 else ''}")
        used_at = datetime.now(timezone.utc)
        expires_at = used_at + timedelta(days=30 * plan_months)

        col_user_ids.update_one(
            {"gym_id": gym_id, "code": code, "status": "active"},
            {"$set": {"status": "used", "used_at": used_at, "used_by": email, "expires_at": expires_at}},
        )
        col_gyms.update_one({"gym_id": gym_id}, {"$inc": {"members": 1}})

    hashed = bcrypt.hashpw(req.password.encode(), bcrypt.gensalt()).decode()

    col_users.insert_one({
        "email": email, "name": req.name.strip(), "password": hashed,
        "weight_kg": req.weight_kg, "height_cm": req.height_cm,
        "gym_id": req.gym_id or None, "plan_months": plan_months, "plan_label": plan_label,
        "indie_plan": False, "membership_expired": False, "workout_plans_locked": True,
        "created_at": datetime.now(timezone.utc),
    })
    return {"status": "created", "email": email, "plan_months": plan_months, "plan_label": plan_label}

@router.get("/admin/users")
def list_users():
    docs = list(col_users.find().sort("created_at", DESCENDING))
    return [
        {
            "email": d["email"], "name": d["name"],
            "weight_kg": d["weight_kg"], "height_cm": d["height_cm"],
            "gym_id": d.get("gym_id"), "indie_plan": d.get("indie_plan", False),
            "plan_months": d.get("plan_months", 1), "plan_label": d.get("plan_label", "1 Month"),
            "membership_expired": d.get("membership_expired", False),
            "created_at": fmt_dt(d.get("created_at")),
        }
        for d in docs
    ]

@router.delete("/admin/users/{email}")
def remove_user(email: str):
    result = col_users.delete_one({"email": email.lower()})
    if result.deleted_count == 0:
        raise HTTPException(404, "User not found")
    return {"status": "deleted"}