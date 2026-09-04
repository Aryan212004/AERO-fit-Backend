import uuid, threading
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException
from pymongo import DESCENDING
from database import col_notifs, col_gyms
from models import NotificationCreate
from utils import doc
from fcm import send_fcm_push

router = APIRouter(tags=["notifications"])

@router.post("/gym/{gym_id}/notifications")
def create_notification(gym_id: str, req: NotificationCreate):
    if not col_gyms.find_one({"gym_id": gym_id}):
        raise HTTPException(404, "Gym not found")
    if req.gym_id != gym_id:
        raise HTTPException(403, "Cannot create notifications for a different gym")

    notif_id = str(uuid.uuid4())
    col_notifs.insert_one({
        "notification_id": notif_id, "gym_id": gym_id, "title": req.title, "body": req.body,
        "type": req.type, "segments": req.segments, "deep_link": req.deep_link or "",
        "scheduled_at": req.scheduled_at or "", "sent_at": datetime.now(timezone.utc),
    })

    threading.Thread(
        target=send_fcm_push, args=(gym_id, req.title, req.body),
        kwargs={"data": {"type": req.type, "gym_id": gym_id, "notif_id": notif_id}},
        daemon=True,
    ).start()

    return {"status": "sent", "notification_id": notif_id}

@router.get("/gym/{gym_id}/notifications")
def list_notifications(gym_id: str):
    if not col_gyms.find_one({"gym_id": gym_id}):
        raise HTTPException(404, "Gym not found")
    docs = list(col_notifs.find({"gym_id": gym_id}).sort("sent_at", DESCENDING).limit(50))
    return [doc(d) for d in docs]

@router.get("/gym/{gym_id}/notifications/member")
def list_member_notifications(gym_id: str):
    if not col_gyms.find_one({"gym_id": gym_id}):
        raise HTTPException(404, "Gym not found")
    docs = list(
        col_notifs.find({"gym_id": gym_id, "segments": {"$nin": ["admin"]}})
        .sort("sent_at", DESCENDING).limit(50)
    )
    return [doc(d) for d in docs]

@router.delete("/gym/{gym_id}/notifications/{notification_id}")
def delete_notification(gym_id: str, notification_id: str):
    if not col_gyms.find_one({"gym_id": gym_id}):
        raise HTTPException(404, "Gym not found")
    result = col_notifs.delete_one({"notification_id": notification_id, "gym_id": gym_id})
    if result.deleted_count == 0:
        raise HTTPException(404, "Notification not found or belongs to a different gym")
    return {"status": "deleted"}