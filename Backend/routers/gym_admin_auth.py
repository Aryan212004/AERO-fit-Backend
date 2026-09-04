import bcrypt
from fastapi import APIRouter, HTTPException
from database import col_gym_admins
from models import AdminLogin

router = APIRouter(prefix="/gym-admin", tags=["gym_admin_auth"])

@router.post("/login")
def gym_admin_login(req: AdminLogin):
    email = req.username.strip().lower()
    adm = col_gym_admins.find_one({"email": email})
    if not adm:
        raise HTTPException(401, "Invalid credentials")
    if adm.get("status") == "inactive":
        raise HTTPException(403, "This admin account has been deactivated")
    if not bcrypt.checkpw(req.password.encode(), adm["password"].encode()):
        raise HTTPException(401, "Invalid credentials")
    return {
        "status": "ok", "role": "gym_admin",
        "admin_id": adm["admin_id"], "gym_id": adm["gym_id"],
        "gym_name": adm["gym_name"], "name": adm["name"], "email": adm["email"],
    }