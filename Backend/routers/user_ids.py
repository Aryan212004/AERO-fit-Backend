from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, HTTPException
from pymongo import DESCENDING
from database import col_user_ids, col_gyms
from models import GenerateUserIdsRequest, ValidateUserIdRequest, UpdateUserIdPlan
from utils import doc, generate_code

router = APIRouter(prefix="/gym/{gym_id}/user-ids", tags=["user_ids"])


@router.post("/generate")
def generate_user_ids(gym_id: str, req: GenerateUserIdsRequest):
    if not col_gyms.find_one({"gym_id": gym_id}):
        raise HTTPException(404, "Gym not found")

    count = max(1, req.count)
    plan_months = max(1, min(req.plan_months, 12))
    plan_label = f"{plan_months} Month{'s' if plan_months > 1 else ''}"
    codes = []
    now = datetime.now(timezone.utc)

    for _ in range(count):
        code = None
        for _attempt in range(10):
            candidate = generate_code()
            if not col_user_ids.find_one({"code": candidate}):
                code = candidate
                break
        if code is None:
            raise HTTPException(500, "Could not generate a unique code, try again")

        col_user_ids.insert_one({
            "gym_id": gym_id, "code": code, "status": "active",
            "plan_months": plan_months, "plan_label": plan_label,
            "created_at": now, "used_at": None, "used_by": None, "expires_at": None,
        })
        codes.append(code)

    print(f"✅  Generated {count} User ID(s) for {gym_id} — plan: {plan_label}", flush=True)
    return {"status": "created", "gym_id": gym_id, "codes": codes, "plan_months": plan_months, "plan_label": plan_label}


@router.get("")
def list_user_ids(gym_id: str):
    if not col_gyms.find_one({"gym_id": gym_id}):
        raise HTTPException(404, "Gym not found")
    docs = list(col_user_ids.find({"gym_id": gym_id}).sort("created_at", DESCENDING))
    return [doc(d) for d in docs]


@router.delete("/{code}")
def revoke_user_id(gym_id: str, code: str):
    code = code.strip().upper()
    result = col_user_ids.delete_one({"gym_id": gym_id, "code": code, "status": "active"})
    if result.deleted_count == 0:
        raise HTTPException(404, "Active code not found")
    return {"status": "revoked", "code": code}


@router.patch("/{code}/plan")
def update_user_id_plan(gym_id: str, code: str, req: UpdateUserIdPlan):
    code = code.strip().upper()
    d = col_user_ids.find_one({"gym_id": gym_id, "code": code})
    if not d:
        raise HTTPException(404, "User ID not found")
    if d.get("status") != "active":
        raise HTTPException(400, "Cannot change plan on a used User ID")
    plan_months = max(1, min(req.plan_months, 12))
    plan_label = f"{plan_months} Month{'s' if plan_months > 1 else ''}"
    col_user_ids.update_one(
        {"gym_id": gym_id, "code": code},
        {"$set": {"plan_months": plan_months, "plan_label": plan_label}},
    )
    print(f"✅  Plan updated → {code}  {plan_label}", flush=True)
    return {"status": "updated", "code": code, "plan_months": plan_months, "plan_label": plan_label}


# Second router for the Flutter app's actual call path:
# POST /gym/{gym_id}/validate-user-id  (not nested under /user-ids)
validate_router = APIRouter(prefix="/gym/{gym_id}", tags=["user_ids"])


@validate_router.post("/validate-user-id")
def validate_user_id(gym_id: str, req: ValidateUserIdRequest):
    code = req.user_id.strip().upper()
    d = col_user_ids.find_one({"gym_id": gym_id, "code": code})
    if not d:
        return {"valid": False, "reason": "Code not found for this gym"}
    if d.get("status") != "active":
        return {"valid": False, "reason": "Code has already been used"}
    return {"valid": True, "plan_months": d.get("plan_months", 1), "plan_label": d.get("plan_label", "1 Month")}