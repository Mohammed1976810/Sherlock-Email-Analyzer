"""Scoring engine — 4-step pipeline replacing the original 9-layer system.

Steps:
  1. COMBINE  — probability-product with per-category density guard
  2. ESCALATE — cluster diversity bonus (single formula, replaces 8 manual rules + 27 correlations)
  3. DAMPEN   — trust factor dampening (multiplicative)
  4. MAP      — score → verdict + confidence

What was removed and why:
  - 27 manual SIGNAL_CORRELATIONS → replaced by automatic diversity bonus in step 2
  - 8 manual CLUSTER_ESCALATIONS → replaced by a single density-scaled formula
  - Signal hierarchy floors → diversity bonus already lifts multi-evidence emails
  - BEC auth-dampening in signal generation → all dampening is now in step 3
  - _legacy_confidence → only analysis_confidence remains
"""
from __future__ import annotations
from typing import List, Dict
from ..models import ThreatSignal, TrustFactor, ScoringResult
from ..constants import CATEGORY_DENSITY, THREAT_CLUSTERS, VERDICT_MAP


def detect_clusters(signals: List[ThreatSignal]) -> Dict[str, List[ThreatSignal]]:
    """Map active signals to threat clusters. Uses set membership + prefix matching."""
    active: Dict[str, List[ThreatSignal]] = {}
    for cname, cdef in THREAT_CLUSTERS.items():
        exact = cdef['exact']
        prefixes = cdef['prefixes']
        matched = [
            s for s in signals
            if s.name in exact or any(s.name.startswith(p) for p in prefixes)
        ]
        if matched:
            active[cname] = matched
    return active


def _cluster_subtotals(active: Dict[str, List[ThreatSignal]]) -> Dict[str, Dict]:
    """Per-cluster combined weight and signal summaries."""
    out = {}
    for cn, sigs in active.items():
        surv = 1.0
        for s in sigs:
            surv *= (1.0 - max(0.0, min(1.0, s.impact)))
        out[cn] = {
            'combined_weight': round(1.0 - surv, 3),
            'signal_count': len(sigs),
            'signal_titles': [s.title for s in sigs if s.probability > 0][:4],
        }
    return out


def run_scoring(signals: List[ThreatSignal],
                trust_factors: List[TrustFactor]) -> ScoringResult:
    """Main scoring pipeline."""
    result = ScoringResult(signals=signals, trust_factors=trust_factors)
    if not signals:
        result.explanation = "No threat signals detected"
        result.analysis_confidence = 95
        return result

    # ── Step 1: COMBINE — probability product with density guard ──────────
    cat_counts: Dict[str, int] = {}
    survival = 1.0
    contributions = []

    for s in sorted(signals, key=lambda x: (x.category, -x.impact)):
        raw_eff = max(0.0, min(1.0, s.impact))
        cat = s.category
        n = cat_counts.get(cat, 0)
        threshold = CATEGORY_DENSITY.get(cat, 3)
        # Diminishing returns: full → 60% → 30%
        dw = 1.0 if n < threshold else (0.60 if n < threshold + 2 else 0.30)
        effective = raw_eff * dw
        cat_counts[cat] = n + 1

        old = 1.0 - survival
        survival *= (1.0 - effective)
        pts = (1.0 - survival) - old
        contributions.append({
            'name': s.name, 'title': s.title, 'tier': s.tier,
            'prob': round(s.probability, 3), 'conf': round(s.confidence, 3),
            'effective': round(effective, 3), 'density_weight': round(dw, 2),
            'pts_added': round(pts * 100, 1),
        })

    combined = 1.0 - survival
    result.signal_contributions = contributions
    result.pre_escalation_score = combined

    # ── Step 2: ESCALATE — cluster diversity bonus ────────────────────────
    # Single formula replaces 8 manual escalation rules + 27 correlations.
    #
    # Logic: escalation_bonus = base_rate × (n_clusters / 4) × avg_confidence × density_factor
    # - 1 cluster: no bonus (single-vector attack)
    # - 2 clusters: base_rate × 0.5 × conf × density
    # - 3 clusters: base_rate × 0.75 × conf × density
    # - 4 clusters: base_rate × 1.0 × conf × density
    #
    # density_factor: avg signals per active cluster / 3, capped at 1.0
    # This ensures a weak single-signal-per-cluster combo gets less bonus than
    # a rich multi-signal-per-cluster combo.
    active_clusters = detect_clusters(signals)
    cluster_subs = _cluster_subtotals(active_clusters)
    result.active_clusters = active_clusters
    result.cluster_signal_subtotals = cluster_subs

    n_active = len(active_clusters)
    cluster_contribs = []

    if n_active >= 2:
        BASE_ESCALATION = 0.35
        all_cluster_sigs = [s for sigs in active_clusters.values() for s in sigs]
        avg_conf = sum(s.confidence for s in all_cluster_sigs) / max(len(all_cluster_sigs), 1)
        avg_density = len(all_cluster_sigs) / max(n_active, 1)
        density_factor = min(1.0, avg_density / 3.0)
        diversity_ratio = n_active / 4.0

        eff_bonus = BASE_ESCALATION * diversity_ratio * avg_conf * density_factor
        before = combined
        combined = min(1.0, combined + eff_bonus * (1.0 - combined))

        cluster_contribs.append({
            'clusters': sorted(active_clusters.keys()),
            'description': f"{n_active}-vector attack pattern detected",
            'bonus': round(BASE_ESCALATION, 3),
            'avg_conf': round(avg_conf, 3),
            'density_factor': round(density_factor, 2),
            'effective_bonus': round(eff_bonus, 3),
            'pts_added': round((combined - before) * 100, 1),
        })
        result.correlations_applied.append(
            f"CLUSTER: {n_active}-vector ({', '.join(sorted(active_clusters.keys()))}) → +{eff_bonus:.2f}")

    result.cluster_contributions = cluster_contribs
    result.pre_dampen_score = combined

    # ── Step 3: DAMPEN — trust factors ────────────────────────────────────
    damp_contribs = []
    for tf in trust_factors:
        d = tf.effective
        if d > 0.005:
            before = combined
            combined *= (1.0 - d)
            damp_contribs.append({
                'name': tf.name, 'description': tf.description,
                'strength': round(tf.strength, 3), 'conf': round(tf.confidence, 3),
                'effective': round(d, 3), 'pts_removed': round((before - combined) * 100, 1),
            })
            result.dampening_applied.append(f"{tf.name} → −{d:.0%}")
    result.dampening_contributions = damp_contribs

    combined = max(0.0, min(1.0, combined))
    result.threat_probability = combined
    result.score = int(combined * 100)

    # ── Step 4: MAP — verdict + confidence ────────────────────────────────
    s = result.score
    for threshold, verdict, level in VERDICT_MAP:
        if s >= threshold:
            result.verdict, result.threat_level = verdict, level
            break

    result.confidence = _analysis_confidence(
        s, signals, trust_factors, n_active, cluster_contribs)
    result.analysis_confidence = result.confidence

    # Dominant vector
    _LABELS = {
        'spoof': "Identity Spoofing", 'payload': "Malware Delivery",
        'infrastructure': "Attacker Infrastructure", 'social_engineering': "Social Engineering / BEC",
    }
    if cluster_contribs:
        labels = [_LABELS.get(c, c) for c in sorted(active_clusters.keys())]
        result.dominant_vector = " + ".join(labels)
    elif active_clusters:
        top = max(active_clusters, key=lambda cn: cluster_subs.get(cn, {}).get('combined_weight', 0))
        result.dominant_vector = _LABELS.get(top, top)
    elif signals:
        top = max(signals, key=lambda x: x.impact)
        cat_label = {'auth': "Auth Bypass", 'behavioral': "Social Engineering",
                     'content': "Content Phishing", 'network': "Suspicious Infrastructure",
                     'attachment': "Malicious Attachment", 'yara': "Malware Signature"
                     }.get(top.category, top.category)
        result.dominant_vector = cat_label

    # Explanation
    top5 = sorted(signals, key=lambda x: x.impact, reverse=True)[:5]
    parts = [f"{t.title} (p={t.probability:.0%}×c={t.confidence:.0%})" for t in top5]
    cl_str = f" Clusters: {', '.join(sorted(active_clusters.keys()))}." if active_clusters else ""
    result.explanation = (f"Score {s}/100 — {len(signals)} signal(s), "
                          f"{len(trust_factors)} trust factor(s).{cl_str} "
                          f"Top: {'; '.join(parts)}")
    return result


def _analysis_confidence(score: int, signals: List[ThreatSignal],
                         trust_factors: List[TrustFactor],
                         n_clusters: int,
                         cluster_contribs: list) -> int:
    """Compute verdict confidence.

    CLEAN (score < 18): "How sure are we this is safe?"
    THREAT (score >= 18): "How well-corroborated is the threat?"
    """
    real = [s for s in signals if not (s.probability == 0.0 and s.name.startswith('bec_')
                                       and s.name != 'bec_combined')]
    n_sig = len(real)
    tf_names = {tf.name for tf in trust_factors}

    if score < 18:
        base = 55
        auth = sum(12 if n in tf_names else 0
                   for n in ('spf_pass', 'dkim_pass')) + (10 if 'dmarc_pass' in tf_names else 0)
        other = min(8, (len(trust_factors) - sum(1 for n in tf_names
                        if n in ('spf_pass', 'dkim_pass', 'dmarc_pass'))) * 3)
        doubt = min(25, n_sig * 7) + sum(12 for s in real if s.tier <= 2)
        return max(15, min(97, base + auth + other - doubt))

    if n_sig == 0:
        return 30
    base = min(65, 25 + n_sig * 10)
    cats = len({s.category for s in real})
    corr = min(15, cats * 5) + min(12, n_clusters * 6)
    tier1 = min(10, sum(1 for s in real if s.tier == 1) * 5)
    trust_pen = min(8, len(trust_factors) * 2)
    thin_pen = 15 if (score >= 65 and n_sig <= 2) else (20 if (score >= 40 and n_sig == 1) else 0)
    return max(10, min(99, base + corr + tier1 - trust_pen - thin_pen))
