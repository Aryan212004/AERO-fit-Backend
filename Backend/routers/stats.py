from fastapi import APIRouter
from database import col_gyms, col_users

router = APIRouter(prefix="/alpha", tags=["stats"])

@router.get("/stats")
def platform_stats():
    gyms = list(col_gyms.find())
    indie_users = col_users.count_documents({"gym_id": None})

    return {
        "total_gyms": len(gyms),
        "active_gyms": sum(1 for g in gyms if g.get("status") == "active"),
        "trial_gyms": sum(1 for g in gyms if g.get("status") == "trial"),
        "pro_gyms": sum(1 for g in gyms if g.get("plan") == "Pro"),
        "total_members": sum(g.get("members", 0) for g in gyms),
        "indie_users": indie_users,
    }