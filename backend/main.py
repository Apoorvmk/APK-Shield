from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
import os
import logging

load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("apkshield-backend")

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Directories
UPLOAD_DIR = os.getenv("UPLOAD_DIR", "/app/uploads")
APKS_DIR = os.path.join(UPLOAD_DIR, "apks")
os.makedirs(APKS_DIR, exist_ok=True)

# Include upload routes from app package
try:
    from app.routes.upload_routes import router as upload_router

    app.include_router(upload_router)
except Exception as e:
    logger.warning("Could not include upload router: %s", e)


@app.get("/api/apk/upload")
async def upload_label():
    return {"label": "upload routes", "upload_endpoint": "/api/apks/upload"}


@app.get("/api/health")
def health():
    return {"status": "ok"}
