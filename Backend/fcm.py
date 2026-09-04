import os
import requests as http_requests
import google.auth.transport.requests
from google.oauth2 import service_account
from config import FIREBASE_PROJECT_ID, FIREBASE_CREDS_PATH

def _get_fcm_token():
    if not FIREBASE_PROJECT_ID or not os.path.exists(FIREBASE_CREDS_PATH):
        return None, None
    creds = service_account.Credentials.from_service_account_file(
        FIREBASE_CREDS_PATH,
        scopes=["https://www.googleapis.com/auth/firebase.messaging"],
    )
    creds.refresh(google.auth.transport.requests.Request())
    return creds.token, FIREBASE_PROJECT_ID

def _base_message(notification_target: dict, title: str, body: str, data: dict) -> dict:
    return {
        "message": {
            **notification_target,
            "notification": {"title": title, "body": body},
            "data": {k: str(v) for k, v in data.items()},
            "android": {
                "priority": "high",
                "notification": {
                    "channel_id": "aerofit_channel",
                    "default_sound": True,
                    "notification_priority": "PRIORITY_HIGH",
                },
            },
            "apns": {
                "headers": {"apns-priority": "10"},
                "payload": {"aps": {"sound": "default", "badge": 1, "content-available": 1}},
            },
        }
    }

def send_fcm_push(gym_id: str, title: str, body: str, data: dict = {}):
    try:
        token, project_id = _get_fcm_token()
        if not token:
            print("⚠️  FCM not configured — skipping push", flush=True)
            return
        payload = _base_message({"topic": f"gym_{gym_id}"}, title, body, data)
        resp = http_requests.post(
            f"https://fcm.googleapis.com/v1/projects/{project_id}/messages:send",
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            json=payload, timeout=10,
        )
        if resp.status_code == 200:
            print(f"✅  FCM push sent → gym={gym_id}  title='{title}'", flush=True)
        else:
            print(f"⚠️  FCM error {resp.status_code}: {resp.json()}", flush=True)
    except Exception as e:
        print(f"⚠️  FCM push failed: {e}", flush=True)

def send_fcm_push_to_token(token_str: str, title: str, body: str, data: dict = {}):
    try:
        if not token_str:
            return
        token, project_id = _get_fcm_token()
        if not token:
            return
        payload = _base_message({"token": token_str}, title, body, data)
        resp = http_requests.post(
            f"https://fcm.googleapis.com/v1/projects/{project_id}/messages:send",
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            json=payload, timeout=10,
        )
        if resp.status_code != 200:
            print(f"⚠️  FCM token-push error {resp.status_code}: {resp.json()}", flush=True)
    except Exception as e:
        print(f"⚠️  FCM token-push failed: {e}", flush=True)