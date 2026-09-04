from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException
from pymongo import DESCENDING
import cloudinary.uploader
from database import col_banners, col_gyms
from models import BannerCreate
from utils import doc
from cloudinary_utils import upload_image
import uuid

router = APIRouter(prefix="/gym/{gym_id}/banners", tags=["banners"])

@router.post("")
def create_banner(gym_id: str, req: BannerCreate):
    if not col_gyms.find_one({"gym_id": gym_id}):
        raise HTTPException(404, "Gym not found")
    if req.gym_id != gym_id:
        raise HTTPException(403, "Cannot create banners for a different gym")
    banner_id = str(uuid.uuid4())
    image_url = upload_image(req.image_base64 or "", folder="aerofitdb/banners", public_id=banner_id)
    doc_ = {
        "banner_id": banner_id, "gym_id": gym_id, "title": req.title, "screen": req.screen,
        "status": req.status, "expires_at": req.expires_at or "", "deep_link": req.deep_link or "",
        "image_url": image_url, "created_at": datetime.now(timezone.utc),
    }
    col_banners.insert_one(doc_)
    return {"status": "created", "banner_id": banner_id, "image_url": image_url}

@router.get("")
def list_banners(gym_id: str, screen: str = None):
    if not col_gyms.find_one({"gym_id": gym_id}):
        raise HTTPException(404, "Gym not found")
    query = {"gym_id": gym_id}
    if screen:
        query["screen"] = screen
    docs = list(col_banners.find(query).sort("created_at", DESCENDING))
    return [doc(d) for d in docs]

@router.delete("/{banner_id}")
def delete_banner(gym_id: str, banner_id: str):
    if not col_gyms.find_one({"gym_id": gym_id}):
        raise HTTPException(404, "Gym not found")
    banner = col_banners.find_one({"banner_id": banner_id, "gym_id": gym_id})
    if not banner:
        raise HTTPException(404, "Banner not found or belongs to a different gym")
    if banner.get("image_url"):
        try:
            cloudinary.uploader.destroy(f"aerofitdb/banners/{banner_id}", resource_type="image")
        except Exception as e:
            print(f"⚠️  Cloudinary delete failed: {e}", flush=True)
    col_banners.delete_one({"banner_id": banner_id, "gym_id": gym_id})
    return {"status": "deleted"}