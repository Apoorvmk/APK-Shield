import os
import logging
import datetime

from celery import Celery
from pymongo import MongoClient
from bson import ObjectId

from app.services.unpacker import unpack_apk
from app.services.yara_scanner import run_yara_scan  # ← new

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
    logger.info(f"[Celery] Starting analysis for sample: {sample_id_str}, sha256: {sha256}, path: {file_path}")

    client = MongoClient(MONGO_URI)
    db = client["apkshield"]
    samples_collection = db["apk_samples"]
    unpacked_collection = db["unpacked_data"]
    manifests_collection = db["manifests"]
    sample_id = ObjectId(sample_id_str)

    # ── Stage 1: Unpack ───────────────────────────────────────────────────────
    try:
        samples_collection.update_one(
            {"_id": sample_id},
            {"$set": {"status": "unpacking", "updated_at": datetime.datetime.now(datetime.timezone.utc)}},
        )
    except Exception:
        logger.exception("Failed to set sample status to unpacking")

    try:
        unpacked_result = unpack_apk(file_path, sha256)
        logger.info(f"[Celery] APK unpack complete for sample: {sample_id_str}")

        manifest_data = unpacked_result["manifest"]
        inventory_data = unpacked_result["inventory"]

        manifest_doc = {
            **manifest_data,
            "sample_id": sample_id,
            "sha256": sha256,
            "created_at": unpacked_result["unpacked_at"],
        }
        manifest_res = manifests_collection.insert_one(manifest_doc)
        manifest_id = manifest_res.inserted_id

    except Exception:
        logger.exception("APK unpack failed for sample: %s", sample_id_str)
        samples_collection.update_one(
            {"_id": sample_id},
            {"$set": {"status": "failed", "updated_at": datetime.datetime.now(datetime.timezone.utc)}},
        )
        raise

    # ── Stage 2: YARA scan ────────────────────────────────────────────────────
    # unpacker writes extracted files to UPLOAD_DIR/unpacked/{sha256}/
    unpacked_dir = os.path.join(UPLOAD_DIR, "unpacked", sha256)

    try:
        samples_collection.update_one(
            {"_id": sample_id},
            {"$set": {"status": "scanning", "updated_at": datetime.datetime.now(datetime.timezone.utc)}},
        )
    except Exception:
        logger.exception("Failed to set sample status to scanning")

    try:
        yara_results = run_yara_scan(apk_path=file_path, unpacked_dir=unpacked_dir)
        logger.info(
            f"[Celery] YARA scan complete for {sample_id_str}: "
            f"{yara_results['yara_hit_count']} hits, "
            f"max_severity={yara_results['yara_max_severity']}"
        )
    except Exception:
        # YARA failure is non-fatal — log and continue with empty results
        logger.exception("YARA scan raised an unexpected exception for sample: %s", sample_id_str)
        yara_results = {
            "yara_hits": [],
            "yara_hit_count": 0,
            "yara_categories": [],
            "yara_max_severity": "none",
            "yara_scan_error": "Scanner crashed — see worker logs",
        }

    # ── Store results ─────────────────────────────────────────────────────────
    now = datetime.datetime.now(datetime.timezone.utc)

    unpacked_doc = {
        **inventory_data,
        **yara_results,               # yara_hits, yara_hit_count, yara_categories, etc.
        "manifest_id": manifest_id,
        "sample_id": sample_id,
        "sha256": sha256,
        "status": unpacked_result["status"],
        "unpacked_path": unpacked_result["unpacked_path"],
        "decompiled_path": unpacked_result["decompiled_path"],
        "decompilation_status": unpacked_result["decompilation_status"],
        "decompilation_error": unpacked_result["decompilation_error"],
        "unpacked_at": unpacked_result["unpacked_at"],
        "updated_at": now,
    }
    res = unpacked_collection.insert_one(unpacked_doc)
    unpacked_data_id = res.inserted_id

    update_doc = {
        "status": "scanned",
        "unpacked_data_id": unpacked_data_id,
        "manifest_id": manifest_id,
        # Manifest summary fields on the sample doc for quick queries
        "package_name": manifest_data.get("package_name"),
        "app_name": manifest_data.get("app_name"),
        "version_name": manifest_data.get("version_name"),
        "version_code": manifest_data.get("version_code"),
        "min_sdk": manifest_data.get("min_sdk"),
        "target_sdk": manifest_data.get("target_sdk"),
        "decompilation_status": unpacked_result.get("decompilation_status"),
        # YARA summary on the sample doc for filtering without a join
        "yara_hit_count": yara_results["yara_hit_count"],
        "yara_categories": yara_results["yara_categories"],
        "yara_max_severity": yara_results["yara_max_severity"],
        "yara_scan_error": yara_results["yara_scan_error"],
        "updated_at": now,
    }
    samples_collection.update_one({"_id": sample_id}, {"$set": update_doc})

    logger.info(
        f"[Celery] Analysis stored for {sample_id_str} — "
        f"status=scanned, yara_hits={yara_results['yara_hit_count']}"
    )

    # ── Next stages (coming soon) ─────────────────────────────────────────────
    # TODO: risk_score = compute_risk_score(manifest_data, yara_results)
    # TODO: explanation = call_claude(risk_score, manifest_data, yara_results)