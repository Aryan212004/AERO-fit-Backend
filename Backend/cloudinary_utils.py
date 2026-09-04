import uuid
import cloudinary
import cloudinary.uploader
from config import CLOUDINARY_CLOUD, CLOUDINARY_API_KEY, CLOUDINARY_SECRET

cloudinary.config(
    cloud_name=CLOUDINARY_CLOUD,
    api_key=CLOUDINARY_API_KEY,
    api_secret=CLOUDINARY_SECRET,
    secure=True,
)
print("✅  Cloudinary configured", flush=True)

def strip_b64_prefix(b64: str) -> str:
    return b64.split(",", 1)[1].strip() if "," in b64 else b64.strip()

def upload_image(base64_str: str, folder: str, public_id: str = None) -> str:
    if not base64_str:
        return ""
    raw = strip_b64_prefix(base64_str)
    data_uri = f"data:image/jpeg;base64,{raw}"
    result = cloudinary.uploader.upload(
        data_uri,
        folder=folder,
        public_id=public_id or str(uuid.uuid4()),
        overwrite=True,
        resource_type="image",
        format="jpg",
        transformation=[{"quality": "auto", "fetch_format": "auto"}],
    )
    return result.get("secure_url", "")