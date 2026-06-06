import os
import logging
import time
import datetime

from celery import Celery
from pymongo import MongoClient
from bson import ObjectId

from app.services.unpacker import unpack_apk

import sys
from pathlib import Path

logger = logging.getLogger("apkshield.celery")
logging.basicConfig(level=logging.INFO)

BROKER_URL = os.getenv("CELERY_BROKER_URL")
RESULT_BACKEND = os.getenv("CELERY_RESULT_BACKEND", BROKER_URL)
MONGO_URI = os.getenv("MONGO_URI")

BACKEND_DIR = Path(__file__).resolve().parent.parent.parent
PROJECT_ROOT = BACKEND_DIR.parent
default_upload_dir = str(PROJECT_ROOT / "uploads") if sys.platform == "win32" else "/app/uploads"
UPLOAD_DIR = os.getenv("UPLOAD_DIR", default_upload_dir)

celery_app = Celery("tasks", broker=BROKER_URL, backend=RESULT_BACKEND)


@celery_app.task(name="analyze_apk")
def analyze_apk(sample_id_str: str, sha256: str):
    file_path = os.path.join(UPLOAD_DIR, "apks", f"{sha256}.apk")
    logger.info(f"[Celery] Starting unpack for sample: {sample_id_str}, sha256: {sha256}, path: {file_path}")

    # Initialize process-specific connection to MongoDB
    client = MongoClient(MONGO_URI)
    db = client["apkshield"]
    samples_collection = db["apk_samples"]
    unpacked_collection = db["unpacked_data"]
    sample_id = ObjectId(sample_id_str)

    # Transition to 'unpacking'
    try:
        samples_collection.update_one(
            {"_id": sample_id},
            {"$set": {"status": "unpacking", "updated_at": datetime.datetime.utcnow()}},
        )
    except Exception:
        logger.exception("Failed to set sample status to unpacking")

    try:
        unpacked_fields = unpack_apk(file_path, sha256)
        logger.info(f"[Celery] APK unpack complete for sample: {sample_id_str}")

        # Store detailed unpacked metadata in a separate collection
        unpacked_doc = {
            **unpacked_fields,
            "sample_id": sample_id,
            "sha256": sha256,
        }
        res = unpacked_collection.insert_one(unpacked_doc)
        unpacked_data_id = res.inserted_id

        # Update the original sample document with high-level info and reference to the detailed metadata
        now = datetime.datetime.utcnow()
        update_doc = {
            "status": "unpacked",
            "unpacked_data_id": unpacked_data_id,
            "package_name": unpacked_fields.get("package_name"),
            "app_name": unpacked_fields.get("app_name"),
            "version_name": unpacked_fields.get("version_name"),
            "version_code": unpacked_fields.get("version_code"),
            "min_sdk": unpacked_fields.get("min_sdk"),
            "target_sdk": unpacked_fields.get("target_sdk"),
            "decompilation_status": unpacked_fields.get("decompilation_status"),
            "updated_at": now,
        }
        samples_collection.update_one(
            {"_id": sample_id},
            {"$set": update_doc},
        )
    except Exception:
        logger.exception("APK unpack failed for sample: %s", sample_id_str)
        samples_collection.update_one(
            {"_id": sample_id},
            {"$set": {"status": "failed", "updated_at": datetime.datetime.utcnow()}},
        )
        raise 
