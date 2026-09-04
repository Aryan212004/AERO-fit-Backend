from pymongo import MongoClient, DESCENDING
from pymongo.collection import Collection
from config import MONGO_URI

_mongo_client: MongoClient = MongoClient(MONGO_URI)
_db_name = MONGO_URI.rsplit("/", 1)[-1].split("?")[0].strip() or "aerofitdb"
mdb = _mongo_client[_db_name]

col_users:            Collection = mdb["users"]
col_banners:          Collection = mdb["banners"]
col_notifs:           Collection = mdb["notifications"]
col_gyms:             Collection = mdb["platform_gyms"]
col_gym_admins:       Collection = mdb["platform_gym_admins"]
col_user_ids:         Collection = mdb["gym_user_ids"]
col_password_resets:  Collection = mdb["password_resets"]
col_signup_otps:      Collection = mdb["indie_signup_otps"]
col_agreements:       Collection = mdb["gym_agreements"]
col_gym_admin_resets: Collection = mdb["gym_admin_password_resets"]
col_trainers:         Collection = mdb["gym_trainers"]
col_batches:          Collection = mdb["gym_batches"]

def init_indexes():
    col_users.create_index("email", unique=True)
    col_banners.create_index("created_at")
    col_banners.create_index([("gym_id", 1), ("created_at", DESCENDING)])
    col_notifs.create_index("sent_at")
    col_notifs.create_index([("gym_id", 1), ("sent_at", DESCENDING)])
    col_gyms.create_index("gym_id", unique=True)
    col_gyms.create_index("admin_email")
    col_gym_admins.create_index("admin_id", unique=True)
    col_gym_admins.create_index("email", unique=True)
    col_gym_admins.create_index("gym_id")
    col_user_ids.create_index([("gym_id", 1), ("code", 1)], unique=True)
    col_user_ids.create_index("code")
    col_user_ids.create_index([("status", 1), ("expires_at", 1)])
    col_password_resets.create_index("email")
    col_password_resets.create_index("expires_at")
    col_signup_otps.create_index("email")
    col_signup_otps.create_index("expires_at")
    col_agreements.create_index("gym_id", unique=True)
    col_agreements.create_index("agreement_id", unique=True)
    col_trainers.create_index([("gym_id", 1), ("created_at", DESCENDING)])
    col_trainers.create_index("trainer_id", unique=True)
    col_gym_admin_resets.create_index("email")
    col_gym_admin_resets.create_index("expires_at")
    col_batches.create_index([("gym_id", 1), ("created_at", DESCENDING)])
    col_batches.create_index("batch_id", unique=True)
    print(f"✅  MongoDB connected → {_db_name}", flush=True)