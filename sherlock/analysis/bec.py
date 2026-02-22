"""BEC detection — tiered keyword matching with ceiling rules.

Simplified: auth dampening removed (handled uniformly in signal generation).
Ceiling logic preserved but consolidated.
"""
from __future__ import annotations
import re
from ..models import BECResult
from ..utils import normalize_text
from ..constants import BEC_KEYWORDS, BEC_CONTRADICTIONS, TIER1_BEC, TIER2_BEC, TIER3_BEC


def analyze_bec(visible_text: str, subject: str, from_addr: str, word_count: int) -> BECResult:
    r = BECResult()
    combined = normalize_text(f"{subject} {visible_text}").lower()
    body_only = normalize_text(visible_text).lower() if visible_text else ""
    if not combined.strip():
        return r

    body_words = len(body_only.split()) if body_only else 0
    total_hits = 0
    survival = 1.0

    for cat, (keywords, prob) in BEC_KEYWORDS.items():
        if not keywords:
            continue
        for kw in keywords:
            if kw in combined:
                r.categories.append(cat)
                r.findings.append(f"[{cat}] '{kw}'")
                total_hits += 1
                if prob > 0:
                    survival *= (1.0 - prob)
                break

    r.score = 1.0 - survival
    r.density = total_hits / max(body_words, 1) if body_words > 0 else 0

    # Contradiction detection
    for urgent_words, calm_words in BEC_CONTRADICTIONS:
        if any(w in combined for w in urgent_words) and any(w in combined for w in calm_words):
            r.contradictions.append("Urgency + calm-language contradiction")
            r.score *= 0.5

    cats = set(r.categories)
    t1 = cats & TIER1_BEC
    t2 = cats & TIER2_BEC
    nonweak = cats - TIER3_BEC
    r.tier1_hit = bool(t1)

    # ── Ceiling rules (consolidated from 6 separate blocks) ───────────────
    _CEILINGS = [
        (not nonweak,                           0.10),   # Only tier-3 → LOW cap
        (len(nonweak) == 1 and t2 and not t1,   0.18),   # Single tier-2, no tier-1 → LOW
        (len(nonweak) == 1 and len(t1) == 1,    0.42),   # Single tier-1 → MEDIUM cap
    ]
    for condition, cap in _CEILINGS:
        if condition:
            r.score = min(r.score, cap)
            break

    # Combination boosters (applied after ceilings)
    _COMBOS = [
        ({'wire_transfer', 'urgency'}, 0.10),
        ({'payment_redirect', 'urgency'}, 0.08),
        ({'authority', 'wire_transfer'}, 0.12), ({'authority', 'gift_cards'}, 0.12),
        ({'secrecy', 'wire_transfer'}, 0.12), ({'secrecy', 'payment_redirect'}, 0.12),
        ({'ceo_fraud', 'secrecy'}, 0.08),
        ({'mfa_bypass', 'urgency'}, 0.06),
    ]
    for required, boost in _COMBOS:
        if required.issubset(cats):
            r.score = r.score + boost * (1.0 - r.score)

    # Category-count gates
    if r.score >= 0.45 and len(nonweak) < 2:
        r.score = min(r.score, 0.42)
    if r.score >= 0.70 and len(t1) < 2 and 'secrecy' not in t1:
        r.score = min(r.score, 0.68)

    # Short-email dampening
    if body_words < 40 and total_hits <= 1 and r.score >= 0.25:
        r.score = min(r.score, 0.22)

    r.score = max(0.0, min(r.score, 0.95))

    # Risk label
    _LEVELS = [(0.70, "CRITICAL", "HIGH-CONFIDENCE BEC"),
               (0.45, "HIGH", "LIKELY BEC"),
               (0.25, "MEDIUM", "BEC indicators"),
               (0.01, "LOW", "Minor BEC signal")]
    for thresh, risk, prefix in _LEVELS:
        if r.score >= thresh:
            r.risk = risk
            r.summary = f"{prefix} (p={r.score:.0%})"
            break
    else:
        r.summary = "No BEC patterns"

    return r
