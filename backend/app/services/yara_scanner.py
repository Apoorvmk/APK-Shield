"""
APKShield — YARA Scanner Service

How it works:
1. Compiles the .yar rules file once at module load (fast on subsequent calls)
2. Scans the raw APK bytes + every file extracted to the unpacked directory
3. Returns a structured dict of hits, severity, and categories

Called from celery_service.py right after unpack_apk() returns.
"""

import logging
import os
from pathlib import Path
from typing import Any

import yara

logger = logging.getLogger("apkshield.yara_scanner")

# ── Rule compilation ──────────────────────────────────────────────────────────
# Compiled once when this module is first imported.
# yara.compile() is thread-safe for matching after compilation.

_RULES_PATH = Path(__file__).parent / "yara_rules" / "banking_malware.yar"
_compiled_rules: yara.Rules | None = None


def _get_rules() -> yara.Rules:
    """Return compiled rules, compiling once on first call."""
    global _compiled_rules
    if _compiled_rules is None:
        if not _RULES_PATH.is_file():
            raise FileNotFoundError(f"YARA rules file not found: {_RULES_PATH}")
        _compiled_rules = yara.compile(filepath=str(_RULES_PATH))
        logger.info(f"YARA rules compiled from {_RULES_PATH}")
    return _compiled_rules


# ── Main entry point ──────────────────────────────────────────────────────────

def run_yara_scan(apk_path: str, unpacked_dir: str) -> dict[str, Any]:
    """
    Scan an APK and its unpacked contents with YARA rules.

    Args:
        apk_path:    Absolute path to the .apk file
        unpacked_dir: Absolute path to the directory where the APK was extracted
                      (written by unpacker.py — contains classes.dex, resources, etc.)

    Returns a dict:
        {
            "yara_hits": [
                {
                    "rule": "SMS_Stealer",
                    "category": "sms_stealer",
                    "severity": "critical",
                    "description": "Reads and exfiltrates...",
                    "matched_file": "classes.dex",
                    "matched_strings": ["getMessageBody", "sendTextMessage"]
                },
                ...
            ],
            "yara_hit_count": 2,
            "yara_categories": ["sms_stealer", "overlay_attack"],
            "yara_max_severity": "critical",   # critical | high | medium | low | none
            "yara_scan_error": null            # error message if scan failed
        }
    """
    hits: list[dict[str, Any]] = []
    scan_error: str | None = None

    try:
        rules = _get_rules()

        # 1. Scan the raw APK file itself
        apk_file_hits = _scan_file(rules, apk_path, label="raw_apk")
        hits.extend(apk_file_hits)

        # 2. Scan every file in the unpacked directory
        unpacked = Path(unpacked_dir)
        if unpacked.is_dir():
            for file_path in unpacked.rglob("*"):
                if not file_path.is_file():
                    continue
                # Only scan file types that can contain code/strings
                if file_path.suffix.lower() not in _SCANNABLE_EXTENSIONS:
                    continue
                relative_label = str(file_path.relative_to(unpacked))
                file_hits = _scan_file(rules, str(file_path), label=relative_label)
                hits.extend(file_hits)
        else:
            logger.warning(f"Unpacked directory not found: {unpacked_dir} — scanning APK only")

    except FileNotFoundError as exc:
        scan_error = str(exc)
        logger.error(f"YARA scan aborted: {exc}")
    except yara.Error as exc:
        scan_error = f"YARA engine error: {exc}"
        logger.error(scan_error)
    except Exception as exc:
        scan_error = f"Unexpected error during YARA scan: {exc}"
        logger.exception(scan_error)

    # Deduplicate: same rule firing on multiple files → keep all hits but note each file
    # For scoring we only count unique rule names
    unique_rules_seen: set[str] = set()
    deduped_hits: list[dict[str, Any]] = []
    for hit in hits:
        rule_name = hit["rule"]
        if rule_name not in unique_rules_seen:
            unique_rules_seen.add(rule_name)
            deduped_hits.append(hit)
        else:
            # Rule already captured — just add this file to the existing hit's file list
            for existing in deduped_hits:
                if existing["rule"] == rule_name:
                    existing.setdefault("also_matched_in", []).append(hit["matched_file"])
                    break

    categories = [h["category"] for h in deduped_hits]
    max_severity = _compute_max_severity(deduped_hits)

    return {
        "yara_hits": deduped_hits,
        "yara_hit_count": len(deduped_hits),
        "yara_categories": categories,
        "yara_max_severity": max_severity,
        "yara_scan_error": scan_error,
    }


# ── Internal helpers ──────────────────────────────────────────────────────────

# File extensions worth scanning (everything that can hold DEX bytecode or strings)
_SCANNABLE_EXTENSIONS = {
    ".dex",   # Dalvik bytecode — primary target
    ".jar",   # May contain .class files
    ".so",    # Native libs can have hardcoded strings / C2 URLs
    ".xml",   # AndroidManifest, strings.xml, network config
    ".json",  # Config files, C2 endpoints
    ".js",    # WebView-based malware
    "",       # Files with no extension (common in unpacked APKs)
}

_SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0}


def _scan_file(rules: yara.Rules, file_path: str, label: str) -> list[dict[str, Any]]:
    """Scan a single file. Returns a list of hit dicts (empty if no matches)."""
    hits = []
    try:
        matches: list[yara.Match] = rules.match(filepath=file_path, timeout=30)
        for match in matches:
            matched_strings = _extract_matched_strings(match)
            hits.append({
                "rule": match.rule,
                "category": match.meta.get("category", "unknown"),
                "severity": match.meta.get("severity", "medium"),
                "description": match.meta.get("description", ""),
                "matched_file": label,
                "matched_strings": matched_strings,
            })
    except yara.TimeoutError:
        logger.warning(f"YARA scan timed out on {label} — skipping")
    except yara.Error as exc:
        logger.warning(f"YARA error on {label}: {exc} — skipping")
    except Exception as exc:
        logger.warning(f"Unexpected error scanning {label}: {exc} — skipping")
    return hits


def _extract_matched_strings(match: yara.Match) -> list[str]:
    """Pull out the human-readable matched string values from a YARA match."""
    seen: set[str] = set()
    result: list[str] = []
    for string_match in match.strings:
        for instance in string_match.instances:
            try:
                decoded = instance.matched_data.decode("utf-8", errors="replace").strip()
                if decoded and decoded not in seen:
                    seen.add(decoded)
                    result.append(decoded)
            except Exception:
                pass
    return result[:20]  # Cap at 20 matched strings per rule to keep Mongo docs small


def _compute_max_severity(hits: list[dict[str, Any]]) -> str:
    if not hits:
        return "none"
    return max(
        (h.get("severity", "low") for h in hits),
        key=lambda s: _SEVERITY_ORDER.get(s, 0),
        default="none",
    )