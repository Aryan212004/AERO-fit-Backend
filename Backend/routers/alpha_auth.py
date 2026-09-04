from fastapi import APIRouter, HTTPException
from config import ALPHA_USERNAME, ALPHA_PASSWORD
from models import AlphaLogin

router = APIRouter(prefix="/alpha", tags=["alpha_auth"])

@router.post("/login")
def alpha_login(req: AlphaLogin):
    if req.username != ALPHA_USERNAME or req.password != ALPHA_PASSWORD:
        raise HTTPException(401, "Invalid alpha admin credentials")
    return {"status": "ok", "role": "alpha"}