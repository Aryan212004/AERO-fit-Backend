import os, json, re, random, smtplib, bcrypt
from datetime import datetime, timezone, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional, List
import anthropic
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from pymongo import MongoClient, ASCENDING, DESCENDING
from pymongo.errors import DuplicateKeyError
from bson import ObjectId
from bson.errors import InvalidId

ANTHROPIC_API_KEY = "sk-ant-YOUR_ACTUAL_KEY"
MONGO_URI         = "mongodb+srv://Aero-fit:AKARyan@cluster0.6qfrbja.mongodb.net/"
MONGO_DB          = "aerofit"
GMAIL_USER        = "aerofityou@gmail.com"
GMAIL_APP_PASS    = "epqp dhgp tmnb bmus"

app = FastAPI(title="AERO-FIT API", version="3.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

mongo_client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
mongo_client.server_info()
db = mongo_client[MONGO_DB]
print(f"✅  MongoDB connected → {MONGO_DB}")

users_col    = db["users"]
otps_col     = db["otps"]
meals_col    = db["meals"]
wardrobe_col = db["wardrobe"]

users_col.create_index([("email", ASCENDING)], unique=True)
otps_col.create_index([("email", ASCENDING)])
otps_col.create_index([("expires_at", ASCENDING)], expireAfterSeconds=0)
meals_col.create_index([("email", ASCENDING), ("logged_at", DESCENDING)])
wardrobe_col.create_index([("email", ASCENDING)])

ai    = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
MODEL = "claude-sonnet-4-20250514"

def _img(b64, mt="image/jpeg"):
    if "," in b64: b64 = b64.split(",",1)[1]
    return {"type":"image","source":{"type":"base64","media_type":mt,"data":b64}}

def _extract_json(text):
    m = re.search(r"\{.*\}", text, re.DOTALL)
    if not m: raise ValueError(f"No JSON: {text[:300]}")
    return json.loads(m.group())

def _str_id(doc):
    if doc and "_id" in doc: doc["_id"] = str(doc["_id"])
    return doc

def send_otp_email(to_email, otp):
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"🔐 {otp} is your AERO-FIT code"
        msg["From"]    = f"AERO-FIT <{GMAIL_USER}>"
        msg["To"]      = to_email
        msg.attach(MIMEText(f"Your AERO-FIT code: {otp}", "plain"))
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as s:
            s.login(GMAIL_USER, GMAIL_APP_PASS)
            s.sendmail(GMAIL_USER, to_email, msg.as_string())
        print(f"✅  OTP sent to {to_email}")
        return True
    except Exception as e:
        print(f"❌  Email failed: {e} — OTP: {otp}")
        return False

class OtpRequest(BaseModel):
    email: str
class OtpVerifyRequest(BaseModel):
    email: str; otp: str
class UserProfile(BaseModel):
    email: str; name: str; weight_kg: float; height_cm: float
class UserUpdate(BaseModel):
    name: Optional[str]=None; weight_kg: Optional[float]=None; height_cm: Optional[float]=None
class MealRequest(BaseModel):
    image_base64: str
class LogMealRequest(BaseModel):
    email: str; name: str; kcal: int; protein: int; carbs: int
    fat: int; fiber: int; serving_size: str; image_path: Optional[str]=""
class ClothingRequest(BaseModel):
    image_base64: str
class SaveWardrobeRequest(BaseModel):
    email: str; item_id: str; name: str; category: str
    color: str; description: str; image_path: Optional[str]=""
class WardrobeItem(BaseModel):
    id: str; name: str; category: str; imagePath: str
    color: str; aiDescription: str; image_base64: Optional[str]=None
class OutfitRequest(BaseModel):
    wardrobe: List[WardrobeItem]; occasion: str; user_photo_base64: Optional[str]=None

@app.get("/health")
def health():
    return {"status":"ok","db":"connected"}

@app.post("/send-otp")
def send_otp(req: OtpRequest):
    email = req.email.strip().lower()
    if not re.match(r"^[\w\.-]+@[\w\.-]+\.\w{2,}$", email):
        raise HTTPException(400, "Invalid email")
    otp = str(random.randint(100000,999999))
    otp_hash = bcrypt.hashpw(otp.encode(), bcrypt.gensalt()).decode()
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)
    otps_col.delete_many({"email":email})
    otps_col.insert_one({"email":email,"otp_hash":otp_hash,"expires_at":expires_at,"used":False,"attempts":0})
    return {"status":"sent","email":email,"email_sent":send_otp_email(email,otp),"expires_in":600}

@app.post("/verify-otp")
def verify_otp(req: OtpVerifyRequest):
    email = req.email.strip().lower()
    record = otps_col.find_one({"email":email,"used":False})
    if not record: raise HTTPException(400,"No active OTP")
    if datetime.now(timezone.utc) > record["expires_at"].replace(tzinfo=timezone.utc):
        otps_col.delete_one({"_id":record["_id"]}); raise HTTPException(400,"Code expired")
    if record.get("attempts",0) >= 5:
        otps_col.delete_one({"_id":record["_id"]}); raise HTTPException(400,"Too many attempts")
    if not bcrypt.checkpw(req.otp.strip().encode(), record["otp_hash"].encode()):
        otps_col.update_one({"_id":record["_id"]},{"$inc":{"attempts":1}})
        raise HTTPException(400,f"Incorrect code. {5-record.get('attempts',0)-1} left.")
    otps_col.update_one({"_id":record["_id"]},{"$set":{"used":True}})
    user = users_col.find_one({"email":email})
    if user:
        return {"status":"verified","is_new":False,"user":{"email":user["email"],"name":user["name"],"weight_kg":user["weight_kg"],"height_cm":user["height_cm"]}}
    return {"status":"verified","is_new":True,"user":None}

@app.post("/save-profile")
def save_profile(req: UserProfile):
    email = req.email.strip().lower()
    try:
        users_col.insert_one({"email":email,"name":req.name.strip(),"weight_kg":req.weight_kg,"height_cm":req.height_cm,"created_at":datetime.now(timezone.utc),"updated_at":datetime.now(timezone.utc)})
        return {"status":"created","email":email}
    except DuplicateKeyError:
        users_col.update_one({"email":email},{"$set":{"name":req.name.strip(),"weight_kg":req.weight_kg,"height_cm":req.height_cm,"updated_at":datetime.now(timezone.utc)}})
        return {"status":"updated","email":email}

@app.get("/user/{email}")
def get_user(email: str):
    user = users_col.find_one({"email":email.lower()})
    if not user: raise HTTPException(404,"User not found")
    return {"email":user["email"],"name":user["name"],"weight_kg":user["weight_kg"],"height_cm":user["height_cm"]}

@app.put("/user/{email}")
def update_user(email: str, req: UserUpdate):
    update = {"updated_at":datetime.now(timezone.utc)}
    if req.name is not None: update["name"]=req.name
    if req.weight_kg is not None: update["weight_kg"]=req.weight_kg
    if req.height_cm is not None: update["height_cm"]=req.height_cm
    if not users_col.update_one({"email":email.lower()},{"$set":update}).matched_count:
        raise HTTPException(404,"User not found")
    return {"status":"updated"}

@app.post("/analyze-meal")
def analyze_meal(req: MealRequest):
    try:
        res = ai.messages.create(model=MODEL, max_tokens=512, messages=[{"role":"user","content":[_img(req.image_base64),{"type":"text","text":'Return ONLY valid JSON: {"name":"<dish>","serving_size":"<size>","kcal":<int>,"protein":<int>,"carbs":<int>,"fat":<int>,"fiber":<int>,"notes":"<tip>"}'}]}])
        d = _extract_json(res.content[0].text)
        return {"name":str(d.get("name","Meal")),"serving_size":str(d.get("serving_size","1 serving")),"kcal":int(d.get("kcal",0)),"protein":int(d.get("protein",0)),"carbs":int(d.get("carbs",0)),"fat":int(d.get("fat",0)),"fiber":int(d.get("fiber",0)),"notes":str(d.get("notes",""))}
    except Exception as e: raise HTTPException(500,str(e))

@app.post("/log-meal")
def log_meal(req: LogMealRequest):
    result = meals_col.insert_one({"email":req.email.lower(),"name":req.name,"kcal":req.kcal,"protein":req.protein,"carbs":req.carbs,"fat":req.fat,"fiber":req.fiber,"serving_size":req.serving_size,"image_path":req.image_path,"logged_at":datetime.now(timezone.utc)})
    return {"status":"logged","meal_id":str(result.inserted_id)}

@app.get("/meals/{email}")
def get_meals(email: str, days: int=1):
    since = datetime.now(timezone.utc)-timedelta(days=days)
    return [_str_id(d) for d in meals_col.find({"email":email.lower(),"logged_at":{"$gte":since}},sort=[("logged_at",DESCENDING)])]

@app.delete("/meal/{meal_id}")
def delete_meal(meal_id: str):
    try: oid=ObjectId(meal_id)
    except InvalidId: raise HTTPException(400,"Invalid ID")
    if not meals_col.delete_one({"_id":oid}).deleted_count: raise HTTPException(404,"Not found")
    return {"status":"deleted"}

@app.post("/analyze-clothing")
def analyze_clothing(req: ClothingRequest):
    try:
        res = ai.messages.create(model=MODEL, max_tokens=256, messages=[{"role":"user","content":[_img(req.image_base64),{"type":"text","text":'Return ONLY valid JSON: {"name":"<item>","category":"<Tops|Bottoms|Shoes|Accessories|Outerwear|Other>","color":"<color>","description":"<desc>"}'}]}])
        d = _extract_json(res.content[0].text)
        return {"name":str(d.get("name","Item")),"category":str(d.get("category","Other")),"color":str(d.get("color","Unknown")),"description":str(d.get("description",""))}
    except Exception as e: raise HTTPException(500,str(e))

@app.post("/save-wardrobe")
def save_wardrobe_item(req: SaveWardrobeRequest):
    wardrobe_col.insert_one({"email":req.email.lower(),"item_id":req.item_id,"name":req.name,"category":req.category,"color":req.color,"description":req.description,"image_path":req.image_path,"added_at":datetime.now(timezone.utc)})
    return {"status":"saved","item_id":req.item_id}

@app.get("/wardrobe/{email}")
def get_wardrobe(email: str):
    return [_str_id(d) for d in wardrobe_col.find({"email":email.lower()},sort=[("added_at",DESCENDING)])]

@app.delete("/wardrobe/{email}/{item_id}")
def delete_wardrobe_item(email: str, item_id: str):
    if not wardrobe_col.delete_one({"email":email.lower(),"item_id":item_id}).deleted_count:
        raise HTTPException(404,"Not found")
    return {"status":"deleted"}

@app.post("/generate-outfit")
def generate_outfit(req: OutfitRequest):
    if not req.wardrobe: raise HTTPException(400,"Wardrobe empty")
    wardrobe_text = "\n".join(f"  ID={i.id} | {i.name} | {i.category} | {i.color} | {i.aiDescription}" for i in req.wardrobe)
    blocks = []
    if req.user_photo_base64:
        blocks.append(_img(req.user_photo_base64))
        blocks.append({"type":"text","text":"Above is the person."})
    blocks.append({"type":"text","text":f'Occasion: {req.occasion}\nWardrobe:\n{wardrobe_text}\n\nReturn ONLY valid JSON: {{"outfit_item_ids":["id1","id2"],"style_note":"<note>","style_score":<70-99>}}'})
    try:
        res = ai.messages.create(model=MODEL,max_tokens=512,messages=[{"role":"user","content":blocks}])
        d = _extract_json(res.content[0].text)
        valid_ids = {w.id for w in req.wardrobe}
        ids = [i for i in d.get("outfit_item_ids",[]) if i in valid_ids] or [w.id for w in req.wardrobe[:3]]
        return {"outfit_item_ids":ids,"style_note":str(d.get("style_note","Great look!")),"style_score":max(60,min(99,int(d.get("style_score",85)))),"occasion":req.occasion}
    except Exception as e: raise HTTPException(500,str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
ENDOFFILE