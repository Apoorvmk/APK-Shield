import os
import logging
import datetime

from celery import Celery
from pymongo import MongoClient
from bson import ObjectId

from app.services.unpacker import unpack_apk
from app.services.yara_scanner import run_yara_scan
from app.services.risk_scorer import compute_risk_score
from app.services.claude_service import generate_explanation

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
    logger.info(f"[Celery] Starting analysis for sample: {sample_id_str}, sha256: {sha256}")

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
            {"$set": {"status": "unpacking", "updated_at": datetime.datetime.utcnow()}},
        )
    except Exception:
        logger.exception("Failed to set sample status to unpacking")

    try:
        unpacked_result = unpack_apk(file_path, sha256)
        logger.info(f"[Celery] Unpack complete for {sample_id_str}")

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
            {"$set": {"status": "failed", "updated_at": datetime.datetime.utcnow()}},
        )
        raise

    # ── Stage 2: YARA scan ────────────────────────────────────────────────────
    unpacked_dir = os.path.join(UPLOAD_DIR, "unpacked", sha256)

    try:
        samples_collection.update_one(
            {"_id": sample_id},
            {"$set": {"status": "scanning", "updated_at": datetime.datetime.utcnow()}},
        )
    except Exception:
        logger.exception("Failed to set sample status to scanning")

    try:
        yara_results = run_yara_scan(apk_path=file_path, unpacked_dir=unpacked_dir)
        logger.info(
            f"[Celery] YARA scan complete for {sample_id_str}: "
            f"{yara_results['yara_hit_count']} hits, max_severity={yara_results['yara_max_severity']}"
        )
    except Exception:
        logger.exception("YARA scan crashed for sample: %s", sample_id_str)
        yara_results = {
            "yara_hits": [],
            "yara_hit_count": 0,
            "yara_categories": [],
            "yara_max_severity": "none",
            "yara_scan_error": "Scanner crashed — see worker logs",
        }

    # ── Stage 3: Risk scoring ─────────────────────────────────────────────────
    try:
        samples_collection.update_one(
            {"_id": sample_id},
            {"$set": {"status": "scoring", "updated_at": datetime.datetime.utcnow()}},
        )
    except Exception:
        logger.exception("Failed to set sample status to scoring")

    try:
        score_result = compute_risk_score(manifest_data, yara_results)
        logger.info(
            f"[Celery] Risk score computed for {sample_id_str}: "
            f"score={score_result['risk_score']}, verdict={score_result['verdict']}"
        )
    except Exception:
        logger.exception("Risk scoring failed for sample: %s", sample_id_str)
        score_result = {
            "risk_score": 0,
            "verdict": "unknown",
            "findings": [],
            "score_breakdown": {},
            "flagged_permissions": [],
            "yara_hit_count": yara_results.get("yara_hit_count", 0),
            "yara_categories": yara_results.get("yara_categories", []),
            "yara_max_severity": yara_results.get("yara_max_severity", "none"),
        }

    # ── Stage 4: Explanation ──────────────────────────────────────────────────
    try:
        samples_collection.update_one(
            {"_id": sample_id},
            {"$set": {"status": "explaining", "updated_at": datetime.datetime.utcnow()}},
        )
    except Exception:
        logger.exception("Failed to set sample status to explaining")

    try:
        app_name = manifest_data.get("app_name")
        package_name = manifest_data.get("package_name")
        explanation = generate_explanation(
            app_name=app_name,
            package_name=package_name,
            risk_score=score_result["risk_score"],
            verdict=score_result["verdict"],
            findings=score_result["findings"],
        )
        logger.info(f"[Celery] Claude explanation complete for {sample_id_str}")
    except Exception:
        logger.exception("Claude explanation crashed for sample: %s", sample_id_str)
        explanation = "Error generating analysis explanation."

    score_result["explanation"] = explanation

    # ── Store everything ──────────────────────────────────────────────────────
    now = datetime.datetime.utcnow()

    unpacked_doc = {
        **inventory_data,
        **yara_results,
        **score_result,
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
        "status": "completed",
        "unpacked_data_id": unpacked_data_id,
        "manifest_id": manifest_id,
        # Manifest summary
        "package_name": manifest_data.get("package_name"),
        "app_name": manifest_data.get("app_name"),
        "version_name": manifest_data.get("version_name"),
        "version_code": manifest_data.get("version_code"),
        "min_sdk": manifest_data.get("min_sdk"),
        "target_sdk": manifest_data.get("target_sdk"),
        "decompilation_status": unpacked_result.get("decompilation_status"),
        # YARA summary
        "yara_hit_count": yara_results["yara_hit_count"],
        "yara_categories": yara_results["yara_categories"],
        "yara_max_severity": yara_results["yara_max_severity"],
        "yara_scan_error": yara_results.get("yara_scan_error"),
        # Score summary — these are what the frontend and Claude call reads
        "risk_score": score_result["risk_score"],
        "verdict": score_result["verdict"],
        "findings": score_result["findings"],
        "explanation": score_result["explanation"],
        "updated_at": now,
    }
    samples_collection.update_one({"_id": sample_id}, {"$set": update_doc})

    logger.info(
        f"[Celery] Pipeline complete for {sample_id_str} — "
        f"verdict={score_result['verdict']}, score={score_result['risk_score']}"
    )