import datetime
import logging
import os
import shutil
import subprocess
import zipfile
from pathlib import Path
from typing import Any

import magic
from androguard.core.apk import APK as AndroguardAPK
from apkutils2 import APK as ApkutilsAPK
from apkutils2.apkfile import ZipFile as ApkutilsZipFile

import sys

logger = logging.getLogger("apkshield.unpacker")

BACKEND_DIR = Path(__file__).resolve().parent.parent.parent
PROJECT_ROOT = BACKEND_DIR.parent
default_upload_dir = str(PROJECT_ROOT / "uploads") if sys.platform == "win32" else "/app/uploads"
UPLOAD_DIR = os.getenv("UPLOAD_DIR", default_upload_dir)
UNPACKED_DIR = os.path.join(UPLOAD_DIR, "unpacked")
DECOMPILED_DIR = os.path.join(UPLOAD_DIR, "decompiled")
JADX_BIN = os.getenv("JADX_BIN", "jadx")
JADX_TIMEOUT_SECONDS = int(os.getenv("JADX_TIMEOUT_SECONDS", "600"))

ZIP_MIME_TYPES = {
    "application/zip",
    "application/java-archive",
    "application/vnd.android.package-archive",
    "application/octet-stream",
}


class UnpackError(RuntimeError):
    """Raised when APK unpacking cannot complete."""


def unpack_apk(file_path: str, sha256: str) -> dict[str, Any]:
    apk_path = Path(file_path)
    if not apk_path.is_file():
        raise UnpackError(f"APK file does not exist: {file_path}")

    _validate_apk_magic(apk_path)

    sample_unpack_dir = _prepare_sample_dir(UNPACKED_DIR, sha256)
    _unpack_raw_contents(apk_path, sample_unpack_dir)

    manifest_data = _parse_manifest_androguard(apk_path)
    inventory = _extract_inventory_apkutils(apk_path)

    sample_decompiled_dir = _prepare_sample_dir(DECOMPILED_DIR, sha256)
    decompile_result = _decompile_with_jadx(apk_path, sample_decompiled_dir)

    now = datetime.datetime.utcnow()
    return {
        "manifest": manifest_data,
        "inventory": inventory,
        "status": "unpacked",
        "unpacked_path": _relative_upload_path(sample_unpack_dir),
        "decompiled_path": _relative_upload_path(sample_decompiled_dir) if decompile_result["success"] else None,
        "decompilation_status": "completed" if decompile_result["success"] else "failed",
        "decompilation_error": decompile_result.get("error"),
        "unpacked_at": now,
        "updated_at": now,
    }


# ── python-magic ──────────────────────────────────────────────────────────────

def _validate_apk_magic(apk_path: Path) -> None:
    with apk_path.open("rb") as fh:
        if fh.read(4) != b"PK\x03\x04":
            raise UnpackError("Invalid APK signature: expected ZIP local file header")

    try:
        mime_type = magic.from_file(str(apk_path), mime=True)
    except Exception as exc:
        raise UnpackError(f"libmagic could not inspect file: {exc}") from exc

    if mime_type not in ZIP_MIME_TYPES:
        raise UnpackError(f"Unexpected MIME type '{mime_type}'; not a ZIP-based package")

    if not zipfile.is_zipfile(apk_path):
        raise UnpackError("File is not a readable ZIP archive")


# ── zip extraction ────────────────────────────────────────────────────────────

def _unpack_raw_contents(apk_path: Path, output_dir: Path) -> None:
    try:
        with ApkutilsZipFile(str(apk_path)) as zf:
            _safe_extract_zip(zf, output_dir)
    except Exception as exc:
        raise UnpackError(f"Failed to extract APK contents: {exc}") from exc


def _safe_extract_zip(apk_zip: Any, output_dir: Path) -> None:
    output_root = output_dir.resolve()
    for member in apk_zip.infolist():
        filename = member.filename if hasattr(member, "filename") else str(member)
        target = (output_root / filename).resolve()
        if target != output_root and output_root not in target.parents:
            raise UnpackError(f"Unsafe archive path detected: {filename}")
    apk_zip.extractall(str(output_root))


# ── androguard — manifest + signing ──────────────────────────────────────────

def _serialize_manifest_xml(manifest_xml: Any) -> str | None:
    """Serialize an androguard manifest element to XML string.

    Tries lxml first (pretty-printed); falls back to stdlib ET if lxml is
    unavailable or raises, since lxml elements implement the ElementTree API.
    """
    try:
        from lxml import etree as lxml_etree
        return lxml_etree.tostring(
            manifest_xml, encoding="utf-8", pretty_print=True
        ).decode("utf-8")
    except Exception:
        pass

    try:
        import xml.etree.ElementTree as stdlib_et
        return stdlib_et.tostring(manifest_xml, encoding="unicode")
    except Exception as exc:
        logger.warning("Failed to serialize AndroidManifest.xml: %s", exc)
        return None


def _parse_manifest_androguard(apk_path: Path) -> dict[str, Any]:
    try:
        apk = AndroguardAPK(str(apk_path))
    except Exception as exc:
        raise UnpackError(f"androguard could not parse APK: {exc}") from exc

    activities = _safe_call(apk.get_activities) or []
    services = _safe_call(apk.get_services) or []
    receivers = _safe_call(apk.get_receivers) or []
    providers = _safe_call(apk.get_providers) or []

    manifest_xml = _safe_call(apk.get_android_manifest_xml)
    manifest_xml_str = _serialize_manifest_xml(manifest_xml) if manifest_xml is not None else None

    return {
        # identity
        "package_name": _safe_call(apk.get_package),
        "manifest_xml": manifest_xml_str,
        "app_name": _safe_call(apk.get_app_name),
        "version_name": _safe_call(apk.get_androidversion_name),
        "version_code": _safe_int(_safe_call(apk.get_androidversion_code)),
        # sdk
        "min_sdk": _safe_int(_safe_call(apk.get_min_sdk_version)),
        "target_sdk": _safe_int(_safe_call(apk.get_target_sdk_version)),
        "max_sdk": _safe_int(_safe_call(apk.get_max_sdk_version)),
        "effective_target_sdk": _safe_int(_safe_call(apk.get_effective_target_sdk_version)),
        # components
        "main_activity": _safe_call(apk.get_main_activity),
        "activities": activities,
        "services": services,
        "receivers": receivers,
        "providers": providers,
        "intent_filters": {
            "activities": _intent_filters_for(apk, "activity", activities),
            "services": _intent_filters_for(apk, "service", services),
            "receivers": _intent_filters_for(apk, "receiver", receivers),
        },
        # permissions
        "permissions": sorted(_safe_call(apk.get_permissions) or []),
        "declared_permissions": list(_safe_call(apk.get_declared_permissions) or []),
        # features & libraries
        "uses_features": list(_safe_call(apk.get_features) or []),
        "uses_libraries": list(_safe_call(apk.get_libraries) or []),
        # signing
        "signature_names": list(_safe_call(apk.get_signature_names) or []),
    }


def _intent_filters_for(apk: AndroguardAPK, component_type: str, names: list[str]) -> dict[str, Any]:
    filters: dict[str, Any] = {}
    for name in names:
        try:
            f = apk.get_intent_filters(component_type, name)
        except Exception:
            logger.exception("Failed to read %s intent filters for %s", component_type, name)
            continue
        if f:
            filters[name] = f
    return filters


# ── apkutils2 — file inventory ────────────────────────────────────────────────

def _extract_inventory_apkutils(apk_path: Path) -> dict[str, Any]:
    try:
        apk = ApkutilsAPK(str(apk_path))
    except Exception as exc:
        logger.warning("apkutils2 could not open APK: %s", exc)
        return {"dex_files": [], "native_libs": [], "apk_files": []}

    dex_files: list[str] = []
    native_libs: list[str] = []
    apk_files: list[str] = []

    try:
        for entry in apk.get_files() or []:
            name = entry.get("name", "") if isinstance(entry, dict) else str(entry)
            apk_files.append(name)
            if name.endswith(".dex"):
                dex_files.append(name)
            elif name.endswith(".so"):
                native_libs.append(name)
    except Exception:
        logger.exception("apkutils2 get_files failed")

    try:
        raw_dex = apk.get_dex_files()
        if raw_dex:
            dex_files = sorted({*dex_files, *[str(d) for d in raw_dex]})
    except Exception:
        logger.exception("apkutils2 get_dex_files failed")

    return {
        "dex_files": sorted(dex_files),
        "native_libs": sorted(native_libs),
        "apk_files": sorted(apk_files),
    }


# ── jadx — decompilation (best-effort) ───────────────────────────────────────

def _decompile_with_jadx(apk_path: Path, output_dir: Path) -> dict[str, Any]:
    command = [
        JADX_BIN, "--deobf", "--show-bad-code",
        "--output-dir", str(output_dir),
        str(apk_path),
    ]
    try:
        result = subprocess.run(
            command, check=False, capture_output=True,
            text=True, timeout=JADX_TIMEOUT_SECONDS,
        )
    except FileNotFoundError:
        msg = f"jadx not found at '{JADX_BIN}'"
        logger.warning(msg)
        return {"success": False, "error": msg}
    except subprocess.TimeoutExpired:
        msg = f"jadx timed out after {JADX_TIMEOUT_SECONDS}s"
        logger.warning(msg)
        return {"success": False, "error": msg}

    if result.returncode != 0:
        stderr = result.stderr.strip() or result.stdout.strip()
        msg = f"jadx exited {result.returncode}: {stderr[:300]}"
        logger.warning(msg)
        return {"success": False, "error": msg}

    return {"success": True}


# ── helpers ───────────────────────────────────────────────────────────────────

def _prepare_sample_dir(base_dir: str, sha256: str) -> Path:
    root = Path(base_dir).resolve()
    sample_dir = (root / sha256).resolve()
    if root not in sample_dir.parents:
        raise UnpackError(f"Refusing unsafe output directory: {sample_dir}")
    if sample_dir.exists():
        shutil.rmtree(sample_dir)
    sample_dir.mkdir(parents=True, exist_ok=True)
    return sample_dir


def _relative_upload_path(path: Path) -> str:
    upload_root = Path(UPLOAD_DIR).resolve()
    try:
        return str(Path("uploads") / path.resolve().relative_to(upload_root)).replace("\\", "/")
    except ValueError:
        return str(path)


def _safe_int(value: Any) -> int | None:
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _safe_call(fn) -> Any:
    try:
        return fn()
    except Exception:
        return None
