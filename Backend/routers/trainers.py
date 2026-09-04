import uuid
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException
from pymongo import DESCENDING
from database import col_trainers, col_gyms, col_users
from models import TrainerCreate, TrainerUpdate
from utils import doc

router = APIRouter(prefix="/gym/{gym_id}/trainers", tags=["trainers"])

@router.post("")
def create_trainer(gym_id: str, req: TrainerCreate):
    if not col_gyms.find_one({"gym_id": gym_id}):
        raise HTTPException(404, "Gym not found")
    if not req.name.strip():
        raise HTTPException(400, "Trainer name is required")

    trainer_id = str(uuid.uuid4())
    doc_ = {
        "trainer_id": trainer_id, "gym_id": gym_id, "name": req.name.strip(),
        "specialty": req.specialty.strip(), "experience_years": max(0, req.experience_years),
        "phone": req.phone.strip(),
        "certifications": [c.strip() for c in req.certifications if c.strip()],
        "created_at": datetime.now(timezone.utc),
    }
    col_trainers.insert_one(doc_)
    print(f"✅  Trainer created → {trainer_id}  gym={gym_id}  '{req.name}'", flush=True)
    return {"status": "created", "trainer_id": trainer_id}

@router.get("")
def list_trainers(gym_id: str):
    if not col_gyms.find_one({"gym_id": gym_id}):
        raise HTTPException(404, "Gym not found")
    docs = list(col_trainers.find({"gym_id": gym_id}).sort("created_at", DESCENDING))
    return [doc(d) for d in docs]

@router.patch("/{trainer_id}")
def update_trainer(gym_id: str, trainer_id: str, req: TrainerUpdate):
    trainer = col_trainers.find_one({"trainer_id": trainer_id, "gym_id": gym_id})
    if not trainer:
        raise HTTPException(404, "Trainer not found for this gym")

    update: dict = {}
    if req.name is not None: update["name"] = req.name.strip()
    if req.specialty is not None: update["specialty"] = req.specialty.strip()
    if req.experience_years is not None: update["experience_years"] = max(0, req.experience_years)
    if req.phone is not None: update["phone"] = req.phone.strip()
    if req.certifications is not None:
        update["certifications"] = [c.strip() for c in req.certifications if c.strip()]

    if update:
        col_trainers.update_one({"trainer_id": trainer_id, "gym_id": gym_id}, {"$set": update})
    return {"status": "updated", "trainer_id": trainer_id}

@router.delete("/{trainer_id}")
def delete_trainer(gym_id: str, trainer_id: str):
    result = col_trainers.delete_one({"trainer_id": trainer_id, "gym_id": gym_id})
    if result.deleted_count == 0:
        raise HTTPException(404, "Trainer not found or belongs to a different gym")
    col_users.update_many(
        {"gym_id": gym_id, "assigned_trainer_id": trainer_id},
        {"$set": {"workout_plans_locked": True},
         "$unset": {"assigned_trainer_id": "", "assigned_trainer_name": "",
                    "assigned_trainer_specialty": "", "assigned_trainer_experience": "",
                    "assigned_trainer_phone": "", "assigned_trainer_certs": ""}},
    )
    return {"status": "deleted"}