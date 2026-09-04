import os, uuid
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException
import cloudinary.uploader
import requests as http_requests
from database import col_agreements, col_gyms
from models import AgreementSubmit
from utils import doc
from cloudinary_utils import upload_image

router = APIRouter(prefix="/gym/{gym_id}/agreement", tags=["agreement"])

AGREEMENT_TEXT = """GYM PARTNERSHIP & SERVICE AGREEMENT

This Agreement is entered into on {agreement_date} between:

AERO-VISUALS (The Company), the owner and operator of the AERO-FIT application,
AND
{gym_name} ("Gym/Admin"), represented by {admin_name}, holding identification
proof: {id_type} (ID No: {id_number_masked}).

1. SCOPE OF SERVICES
Aero-Visuals shall provide access to the AERO-FIT Gym Management Dashboard,
member tracking, workout guidance, activity tracking, and related features
as available on the platform, free of charge.

2. RESPONSIBILITIES OF THE GYM/ADMIN
a. Provide accurate gym and identification information.
b. Use the platform in compliance with applicable laws.
c. Not misuse, resell, or unauthorizedly redistribute platform access.

3. TERM & TERMINATION
This Agreement remains valid as long as the Gym/Admin account is active on
AERO-FIT. Either party may terminate this agreement with written notice.

4. DATA & PRIVACY
Identification and signature data collected are used solely for
verification and legal record-keeping purposes, governed by Aero-Visuals'
Privacy Policy.

5. GOVERNING LAW
This Agreement shall be governed by the laws of India.

By signing below, the Gym/Admin acknowledges having read, understood, and
agreed to all terms stated above.

Admin Name: {admin_name}
Gym Name: {gym_name}
Date: {agreement_date}
ID Proof Type: {id_type}
"""

def _mask_id(id_number: str) -> str:
    id_number = id_number.strip()
    if len(id_number) <= 4:
        return "*" * len(id_number)
    return id_number[:2] + "*" * (len(id_number) - 4) + id_number[-2:]

def _pdf_safe(text: str) -> str:
    return text.encode("latin-1", errors="replace").decode("latin-1")

def _generate_agreement_pdf(gym_name, admin_name, id_type, id_number_masked,
                             signature_local_path, agreement_date) -> bytes:
    from fpdf import FPDF
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(0, 10, "AERO-VISUALS - Gym App Partnership Agreement", ln=True, align="C")
    pdf.ln(4)
    pdf.set_font("Helvetica", "", 10.5)
    body = AGREEMENT_TEXT.format(
        agreement_date=agreement_date, gym_name=gym_name, admin_name=admin_name,
        id_type=id_type, id_number_masked=id_number_masked,
    )
    pdf.multi_cell(0, 5.5, _pdf_safe(body))
    if signature_local_path and os.path.exists(signature_local_path):
        pdf.ln(4)
        pdf.set_font("Helvetica", "B", 10.5)
        pdf.cell(0, 6, "Signature:", ln=True)
        pdf.image(signature_local_path, w=60)
    return bytes(pdf.output(dest="S"))

@router.get("-status")
def agreement_status(gym_id: str):
    gym = col_gyms.find_one({"gym_id": gym_id})
    if not gym:
        raise HTTPException(404, "Gym not found")
    if gym.get("plan") != "Pro":
        return {"required": False}
    agreement = col_agreements.find_one({"gym_id": gym_id})
    return {"required": agreement is None, "signed": agreement is not None}

@router.get("")
def get_agreement(gym_id: str):
    d = col_agreements.find_one({"gym_id": gym_id})
    if not d:
        raise HTTPException(404, "No agreement on file for this gym")
    return doc(d)

@router.post("/submit")
def submit_agreement(gym_id: str, req: AgreementSubmit):
    gym = col_gyms.find_one({"gym_id": gym_id})
    if not gym:
        raise HTTPException(404, "Gym not found")
    if gym.get("plan") != "Pro":
        raise HTTPException(400, "Agreement is only required for Pro plan gyms")
    if col_agreements.find_one({"gym_id": gym_id}):
        raise HTTPException(409, "An agreement has already been submitted for this gym")
    if not req.admin_name.strip() or not req.gym_name.strip() or not req.id_number.strip():
        raise HTTPException(400, "Admin name, gym name, and ID number are required")
    if req.id_type not in ("Aadhar", "Driving License", "Other"):
        raise HTTPException(400, "Invalid ID type")

    agreement_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    agreement_date = now.strftime("%d-%m-%Y")

    sig_url = upload_image(req.signature_base64, folder="aerofitdb/agreements/signatures", public_id=agreement_id)
    id_url = upload_image(req.id_proof_base64, folder="aerofitdb/agreements/id_proofs", public_id=agreement_id)
    if not sig_url:
        raise HTTPException(400, "Signature image is required")
    if not id_url:
        raise HTTPException(400, "ID proof image is required")

    id_number_masked = _mask_id(req.id_number)
    sig_local_path = f"/tmp/sig_{agreement_id}.png"
    try:
        resp = http_requests.get(sig_url, timeout=10)
        with open(sig_local_path, "wb") as f:
            f.write(resp.content)
        pdf_bytes = _generate_agreement_pdf(
            gym_name=req.gym_name.strip(), admin_name=req.admin_name.strip(),
            id_type=req.id_type, id_number_masked=id_number_masked,
            signature_local_path=sig_local_path, agreement_date=agreement_date,
        )
    finally:
        if os.path.exists(sig_local_path):
            os.remove(sig_local_path)

    pdf_upload = cloudinary.uploader.upload(
        pdf_bytes, resource_type="raw", folder="aerofitdb/agreements/pdf",
        public_id=agreement_id, format="pdf", overwrite=True,
    )
    pdf_url = pdf_upload.get("secure_url", "")

    doc_ = {
        "agreement_id": agreement_id, "gym_id": gym_id,
        "admin_name": req.admin_name.strip(), "gym_name": req.gym_name.strip(),
        "id_type": req.id_type, "id_number_masked": id_number_masked,
        "signature_url": sig_url, "id_proof_url": id_url, "agreement_pdf_url": pdf_url,
        "agreement_date": agreement_date, "status": "signed", "created_at": now,
    }
    col_agreements.insert_one(doc_)
    print(f"✅  Agreement signed → gym={gym_id}  admin={req.admin_name}  pdf={pdf_url}", flush=True)
    return {"status": "signed", "agreement_id": agreement_id, "agreement_pdf_url": pdf_url}