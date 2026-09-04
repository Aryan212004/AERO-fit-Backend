from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException
from pymongo import DESCENDING
from database import col_users, col_gyms, col_trainers
from models import WorkoutLockUpdate, FitnessPlanUpdate

router = APIRouter(tags=["workout_access"])

@router.get("/gym/{gym_id}/members")
def list_members(gym_id: str):
    if not col_gyms.find_one({"gym_id": gym_id}):
        raise HTTPException(404, "Gym not found")
    docs = list(col_users.find({"gym_id": gym_id}).sort("created_at", DESCENDING))
    return [
        {
            "email": d["email"],
            "name": d.get("name", ""),
            "workout_plans_locked": d.get("workout_plans_locked", True),
            "assigned_trainer_id": d.get("assigned_trainer_id"),
            "assigned_trainer_name": d.get("assigned_trainer_name", ""),
            "fitness_plan_text": d.get("fitness_plan_text", ""),
        }
        for d in docs
    ]

@router.patch("/gym/{gym_id}/members/{email}/workout-lock")
def set_workout_lock(gym_id: str, email: str, req: WorkoutLockUpdate):
    email = email.strip().lower()
    member = col_users.find_one({"email": email, "gym_id": gym_id})
    if not member:
        raise HTTPException(404, "Member not found for this gym")

    update = {"workout_plans_locked": req.locked, "updated_at": datetime.now(timezone.utc)}

    if not req.locked:
        if not req.trainer_id:
            raise HTTPException(400, "A trainer must be assigned before unlocking Workout Plans")
        trainer = col_trainers.find_one({"trainer_id": req.trainer_id, "gym_id": gym_id})
        if not trainer:
            raise HTTPException(404, "Trainer not found for this gym")
        update.update({
            "assigned_trainer_id": trainer["trainer_id"],
            "assigned_trainer_name": trainer["name"],
            "assigned_trainer_specialty": trainer.get("specialty", ""),
            "assigned_trainer_experience": trainer.get("experience_years", 0),
            "assigned_trainer_phone": trainer.get("phone", ""),
            "assigned_trainer_certs": trainer.get("certifications", []),
        })

    col_users.update_one({"email": email}, {"$set": update})
    print(f"✅  Workout Plans {'locked' if req.locked else 'unlocked'} → {email}  gym={gym_id}", flush=True)
    return {"email": email, "workout_plans_locked": req.locked}

@router.patch("/gym/{gym_id}/members/{email}/fitness-plan")
def set_fitness_plan(gym_id: str, email: str, req: FitnessPlanUpdate):
    email = email.strip().lower()
    member = col_users.find_one({"email": email, "gym_id": gym_id})
    if not member:
        raise HTTPException(404, "Member not found for this gym")
    col_users.update_one(
        {"email": email},
        {"$set": {"fitness_plan_text": req.fitness_plan_text.strip(),
                   "fitness_plan_updated_at": datetime.now(timezone.utc)}},
    )
    return {"status": "updated", "email": email}

@router.get("/user/{email}/workout-plan-info")
def get_workout_plan_info(email: str):
    user = col_users.find_one({"email": email.strip().lower()})
    if not user:
        raise HTTPException(404, "User not found")

    locked = bool(user.get("workout_plans_locked", True))
    trainer = None
    if user.get("assigned_trainer_id"):
        trainer = {
            "trainer_id": user.get("assigned_trainer_id"),
            "name": user.get("assigned_trainer_name", ""),
            "specialty": user.get("assigned_trainer_specialty", ""),
            "experience_years": user.get("assigned_trainer_experience", 0),
            "phone": user.get("assigned_trainer_phone", ""),
            "certifications": user.get("assigned_trainer_certs", []),
        }
    return {"locked": locked, "trainer": trainer, "fitness_plan_text": user.get("fitness_plan_text", "")}

@router.get("/user/{email}/workout-access")
def get_workout_access(email: str):
    user = col_users.find_one({"email": email.strip().lower()})
    if not user:
        raise HTTPException(404, "User not found")
    return {"locked": bool(user.get("workout_plans_locked", True))}