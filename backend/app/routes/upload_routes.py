from fastapi import APIRouter, UploadFile, File, Form, HTTPException, status
from typing import Optional
import os
import hashlib
import datetime
import logging

from pymongo import MongoClient

from app.services.celery_service import analyze_apk

router = APIRouter()

logger = logging.getLogger("apkshield.uploads")

# Directories and limits (can be overridden with env vars)
UPLOAD_DIR = os.getenv("UPLOAD_DIR", "/app/uploads")
APKS_DIR = os.path.join(UPLOAD_DIR, "apks")
os.makedirs(APKS_DIR, exist_ok=True)

MAX_FILE_SIZE = int(os.getenv("MAX_FILE_SIZE", 100 * 1024 * 1024))  # 100 MB default

# MongoDB connection (per-process client)
MONGO_URI = os.getenv("MONGO_URI")
mongo_client = MongoClient(MONGO_URI)
db = mongo_client["apkshield"]
apk_samples_collection = db["apk_samples"]


@router.get("/api/apks/upload")
async def upload_info():
    """Return brief instructions for the upload endpoint."""
    return {
        "message": "POST an APK file to this endpoint with fields: file, source, analysis_mode, description(optional).",
        "sources": ["manual_upload", "bank_portal", "email", "honeypot"],
        "analysis_modes": ["static_only", "full"],
    }


@router.post("/api/apks/upload")
async def upload_apk(
    file: UploadFile = File(...),
    source: str = Form(...),
    description: Optional[str] = Form(None),
    analysis_mode: str = Form("static_only"),
):
    """Receive an APK, validate, store, create DB record and enqueue analysis task."""
    valid_sources = {"manual_upload", "bank_portal", "email", "honeypot"}
    if source not in valid_sources:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid source parameter. Must be one of: {', '.join(valid_sources)}",
        )

    valid_modes = {"static_only", "full"}
    if analysis_mode not in valid_modes:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid analysis_mode. Must be one of: {', '.join(valid_modes)}",
        )

    filename = file.filename or ""
    if not filename.lower().endswith(".apk"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid file extension. Only .apk files are allowed.",
        )

    content = await file.read()
    file_size = len(content)

    if file_size == 0:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Empty file")

    if file_size > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"File size exceeds the limit of {MAX_FILE_SIZE} bytes.",
        )

    # Check ZIP magic bytes
    if len(content) < 4 or content[:4] != b"PK\x03\x04":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid file signature. File must be a ZIP-based package (APK).",
        )

    sha256 = hashlib.sha256(content).hexdigest()

    # Duplicate check
    existing = apk_samples_collection.find_one({"sha256": sha256})
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Duplicate upload: APK with SHA-256 '{sha256}' already exists (Sample ID: {str(existing['_id'])})."
        )

    stored_filename = f"{sha256}.apk"
    storage_path = os.path.join(APKS_DIR, stored_filename)
    with open(storage_path, "wb") as fh:
        fh.write(content)

    relative_storage_path = f"uploads/apks/{stored_filename}"

    now = datetime.datetime.utcnow()
    sample_doc = {
        "original_filename": filename,
        "stored_filename": stored_filename,
        "sha256": sha256,
        "file_size": file_size,
        "content_type": file.content_type or "application/vnd.android.package-archive",
        "storage_type": "local",
        "storage_path": relative_storage_path,
        "source": source,
        "status": "queued",
        "analysis_mode": analysis_mode,
        "description": description,
        "created_at": now,
        "updated_at": now,
    }

    res = apk_samples_collection.insert_one(sample_doc)
    sample_id = res.inserted_id

    # Enqueue Celery task
    try:
        analyze_apk.delay(str(sample_id), sha256, storage_path)
    except Exception as e:
        apk_samples_collection.update_one(
            {"_id": sample_id}, {"$set": {"status": "failed", "updated_at": datetime.datetime.utcnow()}}
        )
        logger.exception("Failed to enqueue analysis task")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to enqueue analysis task")

    logger.info(f"Uploaded APK {stored_filename} queued for analysis (sample_id={sample_id})")

    return {"sample_id": str(sample_id), "status": "queued"}
