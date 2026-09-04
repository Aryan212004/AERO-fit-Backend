import time, threading
from datetime import datetime, timezone, timedelta
from database import col_users, col_user_ids, col_gyms
from utils import ensure_utc

def _keep_alive():
    time.sleep(120)
    while True:
        try:
            import requests as _req
            _req.get("https://aero-fit-backend.onrender.com/health", timeout=5)
            print("✅  Keep-alive ping sent", flush=True)
        except Exception as e:
            print(f"⚠️  Keep-alive failed: {e}", flush=True)
        time.sleep(300)

def _run_expiry_job():
    """Gym membership User-ID expiry only. No indie/billing expiry — plans are free & permanent."""
    time.sleep(30)
    while True:
        try:
            now = datetime.now(timezone.utc)

            expired_ids = list(col_user_ids.find({"status": "used", "expires_at": {"$lte": now}}))
            for uid_doc in expired_ids:
                code, gym_id, used_by = uid_doc.get("code"), uid_doc.get("gym_id"), uid_doc.get("used_by")
                if used_by:
                    col_users.update_one(
                        {"email": used_by},
                        {"$set": {"membership_expired": True, "membership_expired_at": now, "gym_id": None}},
                    )
                    print(f"   ↳ Expired gym user: {used_by}", flush=True)
                col_user_ids.delete_one({"gym_id": gym_id, "code": code})
                col_gyms.update_one(
                    {"gym_id": gym_id, "members": {"$gt": 0}},
                    {"$inc": {"members": -1}},
                )

            expired_trials = list(col_gyms.find({"status": "trial", "trial_expires_at": {"$lte": now}}))
            for gym in expired_trials:
                from routers.gyms import cascade_delete_gym
                print(f"   ↳ Auto-deleting expired trial gym: {gym.get('name')} ({gym.get('gym_id')})", flush=True)
                cascade_delete_gym(gym.get("gym_id"))

        except Exception as e:
            print(f"⚠️  Expiry job error: {e}", flush=True)
        time.sleep(3600)

def start_background_jobs():
    threading.Thread(target=_keep_alive, daemon=True).start()
    threading.Thread(target=_run_expiry_job, daemon=True).start()
    print("✅  Background threads started (keep-alive + expiry job)", flush=True)