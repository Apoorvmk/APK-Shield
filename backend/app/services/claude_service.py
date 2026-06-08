"""
APKShield — Claude Explanation Service

Generates a plain-English security summary and analysis of the scan findings
using Claude, translating technical risk markers into clear explanations for
fraud teams and users.
"""

import os
import logging
from anthropic import Anthropic

logger = logging.getLogger("apkshield.claude")


def generate_explanation(
    app_name: str | None,
    package_name: str | None,
    risk_score: int,
    verdict: str,
    findings: list[str],
) -> str:
    """
    Generate a plain-English security explanation using Claude.
    Falls back to a structured local generator if the API key is missing or calls fail.
    """
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        logger.warning("ANTHROPIC_API_KEY not found in environment. Using fallback explanation.")
        return _get_fallback_explanation(verdict, findings)

    # Format findings list
    findings_str = "\n".join(f"- {f}" for f in findings) if findings else "- No flagged findings."

    # Construct the prompts
    system_prompt = (
        "You are a Senior Mobile Security Analyst specializing in Android banking malware and fraud detection.\n"
        "Your task is to analyze the security scanning findings of an APK and generate a plain-English explanation of the security assessment.\n"
        "This explanation will be read by bank fraud departments, customer support representatives, or end-users.\n"
        "Translate complex technical concepts (like YARA rules, permissions, overlay windows, and signature anomalies) into clear, non-technical risk explanations.\n"
        "Be precise, concise, and professional."
    )

    user_content = (
        f"Please generate a security analysis summary for the following Android application:\n"
        f"- Application Name: {app_name or 'Unknown App'}\n"
        f"- Package Name: {package_name or 'Unknown Package'}\n"
        f"- Verdict: {verdict.upper()}\n"
        f"- Risk Score: {risk_score}/100\n\n"
        f"Technical Findings:\n"
        f"{findings_str}\n\n"
        f"Generate a structured analysis explanation with three distinct, well-separated parts:\n"
        f"1. A clear one-to-two-sentence summary verdict.\n"
        f"2. A non-technical details paragraph explaining the specific risks and threat vectors.\n"
        f"3. A list of actionable recommendations.\n"
        f"Do not include meta-text, markdown headings (like '# Verdict'), or section numbering in your response. Just write the paragraphs/bullets clearly."
    )

    try:
        # Initialize client (uses ANTHROPIC_API_KEY environment variable if api_key is None)
        client = Anthropic(api_key=api_key)

        response = client.messages.create(
            model="claude-3-5-sonnet-20241022",
            max_tokens=1000,
            temperature=0.3,
            system=system_prompt,
            messages=[
                {"role": "user", "content": user_content}
            ]
        )
        content = response.content[0].text
        return content.strip()
    except Exception as e:
        logger.exception("Failed to query Anthropic API: %s", str(e))
        return _get_fallback_explanation(verdict, findings)


def _get_fallback_explanation(verdict: str, findings: list[str]) -> str:
    """Provides a basic, structured explanation when Claude is unavailable."""
    if verdict == "safe":
        summary = "This application has been analyzed and is classified as Safe."
        details = (
            "No critical security threats, suspicious behavior patterns, or dangerous permission requests "
            "were detected. The app signature, versioning, and structure appear normal."
        )
        guidance = (
            "- It is safe to proceed with using this application.\n"
            "- Ensure you downloaded it from an official source (e.g. Google Play Store)."
        )
    elif verdict == "suspicious":
        summary = (
            "This application has been classified as Suspicious due to some sensitive permission requests "
            "or minor structural anomalies."
        )
        details = (
            "The analysis flagged one or more items that merit caution. While there is no direct evidence "
            "of malicious code (YARA rules), the app requests permissions or possesses characteristics that "
            "are unusual for standard banking-related applications."
        )
        guidance = (
            "- Exercise caution before installing or granting permissions to this application.\n"
            "- Verify the source and publisher of the app.\n"
            "- Do not enter sensitive bank credentials unless you are certain of the app's legitimacy."
        )
    else:  # dangerous
        summary = "WARNING: This application is classified as Dangerous and presents a high security risk."
        details = (
            "The scanning engine detected critical risk indicators, which may include known malware signatures "
            "(YARA matches), a combination of dangerous permissions (such as SMS reading and accessibility service "
            "binding), or signature spoofing/impersonation of banking utilities."
        )
        guidance = (
            "- DO NOT install this application. If already installed, uninstall it immediately.\n"
            "- Do not input any login credentials, OTPs, or personal information.\n"
            "- Monitor your mobile banking and financial accounts for unauthorized activity."
        )

    findings_list = "\n".join(f"- {f}" for f in findings) if findings else "- No specific findings."
    return f"{summary}\n\n{details}\n\n**Key Findings Summary:**\n{findings_list}\n\n**Actionable Recommendations:**\n{guidance}"
