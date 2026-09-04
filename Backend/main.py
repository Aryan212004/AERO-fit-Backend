try:
    from pkg_resources import DistributionNotFound
except ImportError:
    import types, sys
    pkg_resources = types.ModuleType("pkg_resources")
    pkg_resources.get_distribution = lambda x: type("D", (), {"version": "0.0.0"})()
    pkg_resources.DistributionNotFound = Exception
    sys.modules["pkg_resources"] = pkg_resources

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from config import ALLOWED_ORIGINS
from database import init_indexes
from background_jobs import start_background_jobs

from routers import (
    health, alpha_auth, gym_admin_auth, gyms, admins, trainers, batches,
    workout_access, user_ids, users, user_auth, indie, all_members,
    banners, notifications, stats, agreement, password_reset,
)

init_indexes()
start_background_jobs()

app = FastAPI(title="AERO-FIT API", version="21.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
    allow_headers=["*"],
    expose_headers=["*", "Retry-After"],
    max_age=3600,
)


@app.options("/{rest_of_path:path}")
async def preflight_handler(request: Request, rest_of_path: str):
    return JSONResponse(content={}, headers={
        "Access-Control-Allow-Origin": request.headers.get("origin", "*"),
        "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS, PATCH",
        "Access-Control-Allow-Headers": "*",
        "Access-Control-Max-Age": "3600",
    })


app.include_router(health.router)
app.include_router(alpha_auth.router)
app.include_router(gym_admin_auth.router)
app.include_router(gyms.router)
app.include_router(admins.router)
app.include_router(trainers.router)
app.include_router(batches.router)
app.include_router(workout_access.router)
app.include_router(user_ids.router)
app.include_router(user_ids.validate_router)   # <-- added: /gym/{gym_id}/validate-user-id
app.include_router(users.router)
app.include_router(user_auth.router)
app.include_router(indie.router)
app.include_router(all_members.router)
app.include_router(banners.router)
app.include_router(notifications.router)
app.include_router(stats.router)
app.include_router(agreement.router)
app.include_router(password_reset.router)

if __name__ == "__main__":
    import os, uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))