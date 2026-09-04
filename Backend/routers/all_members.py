from fastapi import APIRouter
from pymongo import DESCENDING
from database import col_users, col_gyms, col_user_ids
from utils import fmt_dt

router = APIRouter(prefix="/alpha", tags=["all_members"])

@router.get("/members")
def list_all_members():
    docs = list(col_users.find().sort("created_at", DESCENDING))

    gym_ids = {d.get("gym_id") for d in docs if d.get("gym_id")}
    gym_names = {}
    if gym_ids:
        for g in col_gyms.find({"gym_id": {"$in": list(gym_ids)}}, {"gym_id": 1, "name": 1}):
            gym_names[g["gym_id"]] = g.get("name", "")

    emails_with_gym = [d["email"] for d in docs if d.get("gym_id")]
    uid_expiry: dict[str, str] = {}
    if emails_with_gym:
        for uid in col_user_ids.find(
            {"used_by": {"$in": emails_with_gym}, "status": "used"},
            {"used_by": 1, "expires_at": 1}
        ):
            uid_expiry[uid["used_by"]] = fmt_dt(uid.get("expires_at"))

    result = []
    for d in docs:
        email = d.get("email", "")
        weight = d.get("weight_kg", 0)
        height_cm = d.get("height_cm", 0)
        height_m = height_cm / 100 if height_cm else 0
        bmi = round(weight / (height_m ** 2), 1) if height_m > 0 else None

        gym_id = d.get("gym_id")
        gym_name = gym_names.get(gym_id, "") if gym_id else ""
        is_indie = not gym_id
        expires_at = uid_expiry.get(email, "") if gym_id else ""

        result.append({
            "email": email, "name": d.get("name", ""),
            "weight_kg": weight, "height_cm": height_cm, "bmi": bmi,
            "gym_id": gym_id, "gym_name": gym_name,
            "member_type": "indie" if is_indie else "gym",
            "plan_months": d.get("plan_months", 1), "plan_label": d.get("plan_label", "1 Month"),
            "membership_expired": d.get("membership_expired", False),
            "expires_at": expires_at, "created_at": fmt_dt(d.get("created_at")),
        })

    return result