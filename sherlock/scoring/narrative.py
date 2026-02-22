"""Risk Narrative Builder — generates human-readable attack story from signals.

Simplified from 434 lines to ~120. Reads signal.detail/evidence directly
instead of hardcoded name lookups. Phased output (Identity → Payload → Lure).
"""
from __future__ import annotations
from typing import List
from ..models import ThreatSignal, TrustFactor, AuthResult
from ..scoring.engine import detect_clusters
from ..constants import THREAT_CLUSTERS

_PHASE_KEYWORDS = {
    'identity': ('spf', 'dkim', 'dmarc', 'spoof', 'shadow', 'reply-to',
                 'impersonat', 'authentication', 'hijack', 'bec'),
    'payload':  ('attachment', 'malware', 'yara', 'macro', 'ip address',
                 'spamhaus', 'tor', 'pdf', 'executable', 'steganograph',
                 'archive', 'hash', 'virustotal', 'abuse', 'dnsbl', 'mx record'),
    'lure':     ('link', 'url', 'domain', 'typosquat', 'entropy', 'shortener',
                 'credential', 'phishing', 'tld', 'qr'),
}


def build_narrative(signals: List[ThreatSignal],
                    trust_factors: List[TrustFactor],
                    auth: AuthResult,
                    score: int) -> str:
    if score < 18:
        return "No significant threat pattern detected. Email appears clean."

    real = [s for s in signals
            if not (s.probability == 0.0 and s.name.startswith('bec_') and s.name != 'bec_combined')]
    top = sorted(real, key=lambda s: s.impact, reverse=True)
    active = detect_clusters(signals)

    evidence = []
    seen = set()

    def _add(sentence: str):
        key = sentence[:40].lower()
        if key not in seen and sentence:
            seen.add(key)
            evidence.append(sentence)

    # Auth evidence — read directly from AuthResult
    if auth.spf == 'FAIL' and auth.dmarc == 'FAIL':
        _add(f"failed both SPF and DMARC for **{auth.from_domain or 'the sender domain'}**")
    elif auth.spf == 'FAIL':
        _add(f"failed SPF — server not authorized for **{auth.from_domain or 'the domain'}**")
    if auth.shadow_spoof:
        _add(f"uses shadow spoofing — appears from **{auth.from_domain}** but replies route to **{auth.rp_domain}**")

    # Read evidence from actual signal content — never from name lookups
    for s in top[:8]:
        if s.detail and len(s.detail) > 10 and s.impact >= 0.08:
            _add(s.detail[0].lower() + s.detail[1:] if s.detail[0].isupper() else s.detail)
        elif s.title and s.impact >= 0.15:
            _add(f"shows {s.title.lower()}")

    if not evidence:
        for s in top[:3]:
            evidence.append(f"{s.title} (impact: {s.impact:.0%})")

    # Phase assignment
    def _classify(ep: str) -> str:
        el = ep.lower()
        for phase, kws in _PHASE_KEYWORDS.items():
            if any(kw in el for kw in kws):
                return phase
        return 'lure'

    phases = {'identity': [], 'payload': [], 'lure': []}
    for ep in evidence:
        phases[_classify(ep)].append(ep)

    _ICONS = {'identity': '🔴 Identity & Authentication',
              'payload': '💣 Payload & Infrastructure',
              'lure': '🎯 Lure & Social Engineering'}

    sections = []
    for phase, items in phases.items():
        if items:
            if len(items) == 1:
                body = f"This email {items[0]}."
            else:
                body = f"This email {items[0]}, and {items[1]}."
                if len(items) > 2:
                    body += f" It also {'; '.join(items[2:4])}."
            sections.append(f"**{_ICONS[phase]}**\n{body}")

    if not sections:
        sections.append(f"This email {evidence[0]}." if evidence else "Multiple threat indicators detected.")

    # Attack pattern conclusion
    cn = sorted(active.keys())
    if len(cn) >= 3:
        conclusion = " This combination indicates a **sophisticated multi-vector attack**."
    elif 'spoof' in cn and 'payload' in cn:
        conclusion = " Spoofed sender + malicious payload = **initial-access phishing**."
    elif 'spoof' in cn and 'social_engineering' in cn:
        conclusion = " Spoofed sender + social engineering = **Business Email Compromise**."
    elif 'infrastructure' in cn and 'social_engineering' in cn:
        conclusion = " Attacker infrastructure + lure content = **credential phishing**."
    elif len(cn) >= 1:
        conclusion = f" Active threat cluster: **{', '.join(cn)}**."
    else:
        conclusion = ""

    # Recommendation
    rec_map = {
        85: "**BLOCK immediately.** Investigate sender and any interacted links.",
        65: "**QUARANTINE.** Hold for manual review before delivery.",
        40: "**HOLD FOR REVIEW.** Do not deliver without analyst sign-off.",
        0:  "**DELIVER WITH CAUTION.** Consider adding a phishing-warning banner.",
    }
    rec = next(v for k, v in sorted(rec_map.items(), reverse=True) if score >= k)

    return "\n\n".join(sections) + conclusion + f"\n\n**Analyst action:** {rec}"
