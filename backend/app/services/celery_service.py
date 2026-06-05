import os
import logging
import time
import datetime

from celery import Celery
from pymongo import MongoClient
from bson import ObjectId

logger = logging.getLogger("apkshield.celery")
logging.basicConfig(level=logging.INFO)

BROKER_URL = os.getenv("CELERY_BROKER_URL")
RESULT_BACKEND = os.getenv("CELERY_RESULT_BACKEND", BROKER_URL)
MONGO_URI = os.getenv("MONGO_URI")

celery_app = Celery("tasks", broker=BROKER_URL, backend=RESULT_BACKEND)


@celery_app.task(name="analyze_apk")
def analyze_apk(sample_id_str: str, sha256: str, file_path: str):
    logger.info(f"[Celery] Starting static analysis for sample: {sample_id_str}, sha256: {sha256}, path: {file_path}")

    # Initialize process-specific connection to MongoDB
    client = MongoClient(MONGO_URI)
    collection = client["apkshield"]["apk_samples"]

    # Transition to 'static_analysis_running'
    try:
        collection.update_one(
            {"_id": ObjectId(sample_id_str)},
            {"$set": {"status": "static_analysis_running", "updated_at": datetime.datetime.utcnow()}},
        )
    except Exception:
        logger.exception("Failed to set sample status to static_analysis_running")

    # Simulate analysis processing (placeholder)
    try:
        time.sleep(5)
        logger.info(f"[Celery] Mock static analysis complete for sample: {sample_id_str}")
        collection.update_one(
            {"_id": ObjectId(sample_id_str)},
            {"$set": {"status": "completed", "updated_at": datetime.datetime.utcnow()}},
        )
    except Exception:
        logger.exception("Static analysis failed for sample: %s", sample_id_str)
        collection.update_one(
            {"_id": ObjectId(sample_id_str)},
            {"$set": {"status": "failed", "updated_at": datetime.datetime.utcnow()}},
        )
        raise
