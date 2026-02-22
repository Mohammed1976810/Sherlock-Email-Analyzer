"""Content analysis helpers — tracking pixels, suspicious language."""
from __future__ import annotations
import re
from typing import List
from ..utils import normalize_text
from ..constants import SUSPICIOUS_PHRASES


def detect_tracking_pixels(html_body: str) -> List[str]:
    if not html_body:
        return []
    findings = []
    if re.search(r'<img[^>]+width=[\'"]?1[\'"]?[^>]+height=[\'"]?1[\'"]?', html_body, re.I):
        findings.append("1x1 Tracking Pixel")
    n = html_body.replace(" ", "")
    if "color:white" in n or "color:#ffffff" in html_body.lower():
        findings.append("Hidden white text")
    if "font-size:0" in n:
        findings.append("Zero-size font")
    if "display:none" in n:
        findings.append("display:none element")
    return findings


def detect_suspicious_language(visible_text: str, subject: str = "") -> List[str]:
    findings = []
    combined = normalize_text(f"{subject} {visible_text}").lower()
    if len(combined) < 20:
        return findings
    for cat, (phrases, _) in SUSPICIOUS_PHRASES.items():
        for p in phrases:
            try:
                if re.search(p, combined):
                    findings.append(f"Suspicious: '{p}' ({cat})")
                    break
            except Exception:
                if p in combined:
                    findings.append(f"Suspicious: '{p}' ({cat})")
                    break
    return findings
