"""
APKShield — Risk Scoring Engine

Takes the outputs of two already-completed stages:
  - manifest_data  (from unpacker._parse_manifest_androguard)
  - yara_results   (from yara_scanner.run_yara_scan)

Returns a structured score dict that goes into MongoDB and is passed
directly to the Claude explanation call.

Verdict thresholds:
  0–29   → safe
  30–59  → suspicious
  60–100 → dangerous
"""

from __future__ import annotations

from typing import Any

# ── Dangerous permissions ─────────────────────────────────────────────────────
# Each permission maps to (points, reason_string)
# "critical" = direct fraud vector, "high" = serious abuse risk

_PERMISSION_WEIGHTS: dict[str, tuple[int, str]] = {
    # Critical — OTP / SMS theft
    "android.permission.READ_SMS":             (20, "Can read all SMS messages including OTPs"),
    "android.permission.RECEIVE_SMS":          (20, "Intercepts incoming SMS messages in real time"),
    "android.permission.SEND_SMS":             (15, "Can send SMS messages without user knowledge"),

    # Critical — accessibility / overlay abuse
    "android.permission.BIND_ACCESSIBILITY_SERVICE": (20, "Can read screen content and simulate taps on any app"),
    "android.permission.SYSTEM_ALERT_WINDOW":  (20, "Can draw fake overlays over banking apps"),

    # High — device takeover
    "android.permission.RECEIVE_BOOT_COMPLETED": (10, "Starts automatically on device boot"),
    "android.permission.REQUEST_INSTALL_PACKAGES": (15, "Can silently install additional APKs"),
    "android.permission.CHANGE_NETWORK_STATE":  (8,  "Can change network connectivity"),

    # High — notification / clipboard interception
    "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE": (15, "Can read all push notifications including OTPs"),
    "android.permission.READ_CALL_LOG":        (10, "Can read full call history"),
    "android.permission.PROCESS_OUTGOING_CALLS": (10, "Can intercept or redirect outgoing calls"),

    # Medium — surveillance
    "android.permission.READ_CONTACTS":        (8,  "Can read the user's full contact list"),
    "android.permission.ACCESS_FINE_LOCATION": (8,  "Can track precise GPS location"),
    "android.permission.RECORD_AUDIO":         (8,  "Can record microphone without visible indicator"),
    "android.permission.CAMERA":               (5,  "Can access camera"),
    "android.permission.READ_EXTERNAL_STORAGE": (5, "Can read files on device storage"),
    "android.permission.WRITE_EXTERNAL_STORAGE": (5, "Can write files to device storage"),
}

# Permissions that are almost never legitimate in a non-system banking app
_CRITICAL_PERMISSIONS = {
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE",
    "android.permission.REQUEST_INSTALL_PACKAGES",
}

# ── YARA severity weights ─────────────────────────────────────────────────────
_YARA_SEVERITY_POINTS: dict[str, int] = {
    "critical": 30,
    "high":     15,
    "medium":    8,
    "low":       3,
}

# ── Known legitimate bank package prefixes ───────────────────────────────────
# If an app claims to be from these but doesn't match → suspicious
_LEGIT_BANK_PACKAGES = {
    "com.sbi", "com.statebank",
    "com.hdfcbank", "net.one97",
    "com.icicibank", "com.axisbank",
    "com.kotak", "com.paytm",
    "com.phonepe", "com.google.android.apps.nbu",
    "in.org.npci.upiapp",
}


# ── Main entry point ──────────────────────────────────────────────────────────

def compute_risk_score(
    manifest_data: dict[str, Any],
    yara_results: dict[str, Any],
) -> dict[str, Any]:
    """
    Compute a risk score from manifest and YARA data.

    Returns:
        {
            "risk_score": 72,                    # 0–100
            "verdict": "dangerous",              # safe | suspicious | dangerous
            "findings": [                        # list of human-readable strings
                "YARA: SMS_Stealer — Can read and exfiltrate SMS/OTP messages",
                "Permission: READ_SMS — Can read all SMS messages including OTPs",
                ...
            ],
            "score_breakdown": {                 # for transparency / debugging
                "yara_score": 45,
                "permission_score": 40,
                "structure_score": 10,
                "raw_total": 95,
                "capped_score": 100,
            },
            "flagged_permissions": [...],        # subset that contributed points
            "yara_hit_count": 3,
            "yara_categories": [...],
        }
    """
    findings: list[str] = []
    breakdown: dict[str, int] = {
        "yara_score": 0,
        "permission_score": 0,
        "structure_score": 0,
    }

    # ── 1. Score YARA hits ────────────────────────────────────────────────────
    yara_hits: list[dict] = yara_results.get("yara_hits") or []
    for hit in yara_hits:
        severity = hit.get("severity", "medium")
        pts = _YARA_SEVERITY_POINTS.get(severity, 8)
        breakdown["yara_score"] += pts
        rule = hit.get("rule", "Unknown")
        desc = hit.get("description", "")
        findings.append(f"YARA [{severity}]: {rule} — {desc}")

    # ── 2. Score permissions ──────────────────────────────────────────────────
    permissions: list[str] = manifest_data.get("permissions") or []
    flagged_permissions: list[dict] = []

    for perm in permissions:
        if perm in _PERMISSION_WEIGHTS:
            pts, reason = _PERMISSION_WEIGHTS[perm]
            breakdown["permission_score"] += pts
            short_name = perm.split(".")[-1]
            findings.append(f"Permission: {short_name} — {reason}")
            flagged_permissions.append({
                "permission": perm,
                "points": pts,
                "reason": reason,
                "is_critical": perm in _CRITICAL_PERMISSIONS,
            })

    # ── 3. Score structural signals ───────────────────────────────────────────

    # No valid signing certificate
    signature_names: list[str] = manifest_data.get("signature_names") or []
    if not signature_names:
        breakdown["structure_score"] += 15
        findings.append("Structure: No signing certificate found — unsigned or stripped APK")

    # Very old target SDK (below Android 8 Oreo = API 26)
    # Apps targeting old SDKs bypass modern permission restrictions
    target_sdk = manifest_data.get("target_sdk")
    if target_sdk is not None and target_sdk < 26:
        breakdown["structure_score"] += 10
        findings.append(f"Structure: Targets old SDK {target_sdk} (below Android 8) — bypasses modern permission guards")

    # Suspiciously low version code (fake apps often use 1)
    version_code = manifest_data.get("version_code")
    if version_code is not None and version_code <= 1:
        breakdown["structure_score"] += 5
        findings.append(f"Structure: Version code is {version_code} — may be a newly created fake app")

    # Package name impersonation check
    # If the app name or package contains bank keywords but isn't from a known legitimate package
    package_name: str = manifest_data.get("package_name") or ""
    app_name: str = (manifest_data.get("app_name") or "").lower()

    bank_keywords = {"sbi", "hdfc", "icici", "axis", "kotak", "paytm", "phonepe", "bhim", "yono", "upi", "neft", "rtgs"}
    name_has_bank_keyword = any(kw in package_name.lower() or kw in app_name for kw in bank_keywords)
    is_known_legit = any(package_name.startswith(prefix) for prefix in _LEGIT_BANK_PACKAGES)

    if name_has_bank_keyword and not is_known_legit:
        breakdown["structure_score"] += 20
        findings.append(
            f"Structure: Package '{package_name}' uses banking keywords but is not from a known legitimate publisher"
        )

    # No main activity declared (unusual, sometimes seen in malware droppers)
    main_activity = manifest_data.get("main_activity")
    if not main_activity:
        breakdown["structure_score"] += 5
        findings.append("Structure: No main activity declared — app may be a background service or dropper")

    # High number of receivers (common in surveillance/spyware)
    receivers: list = manifest_data.get("receivers") or []
    if len(receivers) >= 5:
        breakdown["structure_score"] += 8
        findings.append(f"Structure: {len(receivers)} broadcast receivers declared — unusually high, common in spyware")

    # ── 4. Total and classify ─────────────────────────────────────────────────
    raw_total = sum(breakdown.values())
    capped = min(raw_total, 100)
    breakdown["raw_total"] = raw_total
    breakdown["capped_score"] = capped

    verdict = _classify(capped)

    return {
        "risk_score": capped,
        "verdict": verdict,
        "findings": findings,
        "score_breakdown": breakdown,
        "flagged_permissions": flagged_permissions,
        "yara_hit_count": yara_results.get("yara_hit_count", 0),
        "yara_categories": yara_results.get("yara_categories", []),
        "yara_max_severity": yara_results.get("yara_max_severity", "none"),
    }


def _classify(score: int) -> str:
    if score >= 60:
        return "dangerous"
    if score >= 30:
        return "suspicious"
    return "safe"