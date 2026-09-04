import uuid
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException
from pymongo import DESCENDING
from database import col_batches, col_gyms, col_users
from models import BatchCreate, BatchUpdate, BatchEnroll
from utils import doc

router = APIRouter(prefix="/gym/{gym_id}/batches", tags=["batches"])

@router.post("")
def create_batch(gym_id: str, req: BatchCreate):
    if not col_gyms.find_one({"gym_id": gym_id}):
        raise HTTPException(404, "Gym not found")
    if not req.name.strip():
        raise HTTPException(400, "Batch name is required")

    batch_id = str(uuid.uuid4())
    doc_ = {
        "batch_id": batch_id, "gym_id": gym_id, "name": req.name.strip(),
        "time": req.time.strip(), "days_label": req.days_label.strip(),
        "trainer_name": req.trainer_name.strip(), "capacity": max(1, req.capacity),
        "enrolled_emails": [], "member_count": max(0, req.member_count),
        "created_at": datetime.now(timezone.utc),
    }
    col_batches.insert_one(doc_)
    print(f"✅  Batch created → {batch_id}  gym={gym_id}  '{req.name}'", flush=True)
    return {"status": "created", "batch_id": batch_id}

@router.get("")
def list_batches(gym_id: str):
    if not col_gyms.find_one({"gym_id": gym_id}):
        raise HTTPException(404, "Gym not found")
    docs = list(col_batches.find({"gym_id": gym_id}).sort("created_at", DESCENDING))
    return [doc(d) for d in docs]

@router.patch("/{batch_id}")
def update_batch(gym_id: str, batch_id: str, req: BatchUpdate):
    batch = col_batches.find_one({"batch_id": batch_id, "gym_id": gym_id})
    if not batch:
        raise HTTPException(404, "Batch not found for this gym")

    update: dict = {}
    if req.name is not None: update["name"] = req.name.strip()
    if req.time is not None: update["time"] = req.time.strip()
    if req.days_label is not None: update["days_label"] = req.days_label.strip()
    if req.trainer_name is not None: update["trainer_name"] = req.trainer_name.strip()
    if req.capacity is not None: update["capacity"] = max(1, req.capacity)
    if req.member_count is not None: update["member_count"] = max(0, req.member_count)

    if update:
        col_batches.update_one({"batch_id": batch_id, "gym_id": gym_id}, {"$set": update})
    return {"status": "updated", "batch_id": batch_id}

@router.delete("/{batch_id}")
def delete_batch(gym_id: str, batch_id: str):
    result = col_batches.delete_one({"batch_id": batch_id, "gym_id": gym_id})
    if result.deleted_count == 0:
        raise HTTPException(404, "Batch not found or belongs to a different gym")
    return {"status": "deleted"}

@router.post("/{batch_id}/enroll")
def enroll_in_batch(gym_id: str, batch_id: str, req: BatchEnroll):
    email = req.email.strip().lower()

    member = col_users.find_one({"email": email, "gym_id": gym_id})
    if not member:
        raise HTTPException(404, "Member not found for this gym")

    batch = col_batches.find_one({"batch_id": batch_id, "gym_id": gym_id})
    if not batch:
        raise HTTPException(404, "Batch not found for this gym")

    enrolled = batch.get("enrolled_emails", [])
    if email in enrolled:
        return {"status": "already_enrolled", "batch_id": batch_id}
    if len(enrolled) >= batch.get("capacity", 20):
        raise HTTPException(400, "This batch is full")

    col_batches.update_one(
        {"batch_id": batch_id, "gym_id": gym_id},
        {"$addToSet": {"enrolled_emails": email}, "$inc": {"member_count": 1}},
    )
    print(f"✅  {email} enrolled in batch {batch_id}  gym={gym_id}", flush=True)
    return {"status": "enrolled", "batch_id": batch_id}

@router.post("/{batch_id}/unenroll")
def unenroll_from_batch(gym_id: str, batch_id: str, req: BatchEnroll):
    email = req.email.strip().lower()

    batch = col_batches.find_one({"batch_id": batch_id, "gym_id": gym_id})
    if not batch:
        raise HTTPException(404, "Batch not found for this gym")
    if email not in batch.get("enrolled_emails", []):
        return {"status": "not_enrolled", "batch_id": batch_id}

    col_batches.update_one(
        {"batch_id": batch_id, "gym_id": gym_id},
        {"$pull": {"enrolled_emails": email}, "$inc": {"member_count": -1}},
    )
    print(f"✅  {email} left batch {batch_id}  gym={gym_id}", flush=True)
    return {"status": "unenrolled", "batch_id": batch_id}