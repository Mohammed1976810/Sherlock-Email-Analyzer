"""Display pre-computation layer — transforms raw analysis result into display-ready data.

Called ONCE after analyze_email() returns. Every value produced here is final —
the Streamlit render pass does zero math, zero filtering, zero string manipulation.

All user-provided content is HTML-escaped. All lists are pre-sorted. All groupings
are pre-computed. Every try/except defaults to a safe empty value.
"""
from __future__ import annotations
import json, re
from typing import List, Dict, Any
from .utils import esc, filter_display_signals, defang, url_host, is_tracking_domain, root_domain
from .ui.styles import DC, SHADOW, tc, ti
from .ui.components import card, signal_card_html, md_to_html
from .constants import MITRE_MAP, VALID_MIMES
from .models import ThreatSignal

# ── Safe accessor ─────────────────────────────────────────────────────────────

def _safe(fn, default=None):
    try:
        return fn()
    except Exception:
        return default


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN ENTRY: prepare_display(R) → dict
# ═══════════════════════════════════════════════════════════════════════════════

def prepare_display(R: dict) -> dict:
    """Transform raw report dict into fully display-ready data.

    Returns a nested dict with keys matching tab names. Every value is
    ready for direct st.markdown() / st.dataframe() / st.metric() use.
    """
    D: Dict[str, Any] = {'raw': R}

    # ── Verdict card ──────────────────────────────────────────────────────
    D['verdict'] = _build_verdict(R)

    # ── Tab 0: Report & Intelligence ──────────────────────────────────────
    D['report'] = _build_report_tab(R)

    # ── Tab 1: Authentication ─────────────────────────────────────────────
    D['auth'] = _build_auth_tab(R)

    # ── Tab 2: URLs & Domains ─────────────────────────────────────────────
    D['urls'] = _build_urls_tab(R)

    # ── Tab 3: Attachments ────────────────────────────────────────────────
    D['attachments'] = _build_attachments_tab(R)

    # ── Tab 4: YARA ───────────────────────────────────────────────────────
    D['yara'] = _build_yara_tab(R)

    # ── Tab 5: Images ─────────────────────────────────────────────────────
    D['images'] = _build_images_tab(R)

    # ── Tab 6: All Findings ───────────────────────────────────────────────
    D['findings'] = _build_findings_tab(R)

    # ── Tab 7: Export ─────────────────────────────────────────────────────
    D['export'] = _build_export_tab(R)

    # ── Tab 8: SOC Integration ────────────────────────────────────────────
    D['soc'] = _build_soc_tab(R)

    return D


# ═══════════════════════════════════════════════════════════════════════════════
# VERDICT CARD
# ═══════════════════════════════════════════════════════════════════════════════

def _build_verdict(R: dict) -> dict:
    s = R.get('score', 0)
    level = R.get('threat_level', 'SAFE')
    color = tc(level)
    icon = ti(level)
    is_clean = s < 18
    ac = R.get('analysis_confidence', R.get('confidence', 50))

    _ACTIONS = [(0, '✅ RELEASE', DC['ok']), (18, '🔍 REVIEW', DC['accent']),
                (40, '⚠️ HOLD', DC['warn']), (65, '⛔ QUARANTINE', DC['critical'])]
    action_label, action_color = '✅ RELEASE', DC['ok']
    for thresh, lbl, col in _ACTIONS:
        if s >= thresh:
            action_label, action_color = lbl, col

    if is_clean:
        ac_color = DC['ok'] if ac >= 70 else (DC['warn'] if ac >= 45 else DC['accent'])
        ac_label = "Confirmed Clean" if ac >= 75 else ("Likely Clean" if ac >= 50 else ("Unverified" if ac >= 30 else "Inconclusive"))
        ac_tip = ("Authentication passed" if ac >= 75 else
                  ("Basic checks pass" if ac >= 50 else
                   ("No auth data" if ac >= 30 else "Insufficient data")))
        cert_header = "Clean Certainty"
    else:
        ac_color = DC['ok'] if ac >= 70 else (DC['warn'] if ac >= 45 else DC['critical'])
        ac_label = "Strong" if ac >= 75 else ("Moderate" if ac >= 50 else ("Weak" if ac >= 30 else "Very Weak"))
        ac_tip = ("Multiple signals agree" if ac >= 75 else
                  ("Some evidence" if ac >= 50 else
                   ("Limited evidence" if ac >= 30 else "Possible false positive")))
        cert_header = "Evidence Strength"

    return {
        'score': s, 'verdict': R.get('verdict', 'CLEAN'), 'threat_level': level,
        'color': color, 'icon': icon, 'is_clean': is_clean,
        'action_label': action_label, 'action_color': action_color,
        'ac_value': ac, 'ac_color': ac_color, 'ac_label': ac_label,
        'ac_tip': ac_tip, 'cert_header': cert_header,
        'dominant_vector': R.get('dominant_vector', ''),
    }


# ═══════════════════════════════════════════════════════════════════════════════
# TAB 0: REPORT & INTELLIGENCE
# ═══════════════════════════════════════════════════════════════════════════════

def _build_report_tab(R: dict) -> dict:
    out: dict = {}
    score = R.get('score', 0)

    # Narrative HTML (pre-rendered)
    narrative = R.get('risk_narrative', '')
    if score >= 18 and narrative:
        out['narrative_html'] = _render_narrative_html(narrative, R)
    else:
        out['narrative_html'] = (
            f"<div style='background:{DC['ok']}18;border-left:5px solid {DC['ok']};"
            f"border-radius:10px;padding:14px 18px;margin:12px 0'>"
            f"<b style='color:{DC['ok']}'>🧠 THREAT NARRATIVE</b><br>"
            f"<span style='color:{DC['text1']}'>No significant threat pattern. Email appears clean.</span></div>")

    # Signal cards (pre-built HTML)
    display_sigs = filter_display_signals(R.get('signals', []))
    top_sigs = sorted(display_sigs, key=lambda x: x.probability * x.confidence, reverse=True)
    cards_html = ""
    for s in top_sigs[:6]:
        eff = s.probability * s.confidence
        cards_html += signal_card_html(s.title, s.detail, s.evidence, eff, s.category)
    out['signal_cards_html'] = cards_html

    # Reasoning cards (pre-built)
    out['reasoning_cards'] = _safe(lambda: _build_reasoning_cards(R), [])

    # Trust factors
    out['trust_factors'] = R.get('trust_factors', [])

    # Correlations (pre-split)
    corrs = R.get('correlations', [])
    out['cluster_corrs'] = [c for c in corrs if c.startswith('CLUSTER:')]
    out['signal_corrs'] = [c for c in corrs if not c.startswith('CLUSTER:')]

    # Recommendation
    _RECS = [(65, '⛔ **QUARANTINE** — Block delivery.', DC['critical']),
             (40, '⚠️ **HOLD FOR REVIEW** — Manual analyst review required.', DC['warn']),
             (18, '🔍 **DELIVER WITH CAUTION** — Add warning banner.', DC['accent']),
             (0,  '✅ **RELEASE** — No significant threats.', DC['ok'])]
    for thresh, note, nc in _RECS:
        if score >= thresh:
            out['rec_html'] = md_to_html(note)
            out['rec_color'] = nc
            break

    # Score breakdown (pre-computed steps)
    out['score_breakdown'] = _build_score_breakdown(R)

    # Metadata
    meta = R.get('metadata', {})
    hashes = R.get('hashes', {})
    out['metadata'] = {
        'from': esc((meta.get('from', '—'))[:80]),
        'subject': esc((meta.get('subject', '—'))[:80]),
        'date': esc((meta.get('date', '—'))[:60]),
        'md5': hashes.get('md5', '—'),
        'sha256': hashes.get('sha256', '—'),
    }

    return out


def _render_narrative_html(narrative: str, R: dict) -> str:
    narr_color = tc(R.get('threat_level', 'SAFE'))
    _PHASE_COLORS = {'🔴': DC['critical'], '💣': DC['high'], '🎯': DC['warn']}
    sections = [s.strip() for s in narrative.split('\n\n') if s.strip()]
    parts = []
    for sec in sections:
        hdr = re.match(r'^\*\*([^*]+)\*\*\n?(.*)', sec, re.DOTALL)
        if hdr:
            hdr_raw, body = hdr.group(1).strip(), hdr.group(2).strip()
            ph_color = next((c for em, c in _PHASE_COLORS.items() if em in hdr_raw), DC['accent'])
            body_html = re.sub(r'\*\*(.+?)\*\*', r'<b style="color:#fff">\1</b>', esc(body))
            parts.append(
                f"<div style='border-left:3px solid {ph_color};padding:6px 12px;margin:8px 0'>"
                f"<div style='color:{ph_color};font-weight:700;font-size:.84em;"
                f"text-transform:uppercase;letter-spacing:.05em;margin-bottom:4px'>{esc(hdr_raw)}</div>"
                f"<div style='color:{DC['text2']};font-size:.90em;line-height:1.6'>{body_html}</div></div>")
        else:
            parts.append(f"<div style='color:{DC['text2']};font-size:.90em;line-height:1.6;margin:6px 0'>"
                         f"{re.sub(r'\\*\\*(.+?)\\*\\*', r'<b style=\"color:#fff\">\\1</b>', esc(sec))}</div>")

    # Cluster badges
    badges_html = ""
    active = R.get('active_clusters', {})
    _BC = {'spoof': '#8b5cf6', 'payload': '#ef4444', 'infrastructure': '#f59e0b', 'social_engineering': '#3b82f6'}
    _BI = {'spoof': '🎭', 'payload': '💣', 'infrastructure': '🌐', 'social_engineering': '🎯'}
    for cn, sigs in active.items():
        bc = _BC.get(cn, DC['accent'])
        titles = [s['title'] if isinstance(s, dict) else str(s) for s in sigs if isinstance(s, dict) and s.get('prob', 1) > 0][:3]
        label = esc(', '.join(titles)) if titles else 'active'
        badges_html += (f"<div style='display:inline-block;background:{bc}18;border:1px solid {bc}77;"
                        f"border-radius:8px;padding:6px 12px;margin:4px 6px 0 0;max-width:300px'>"
                        f"<div style='color:{bc};font-weight:700;font-size:.80em'>"
                        f"{_BI.get(cn, '🔴')} {cn.replace('_', ' ').upper()}</div>"
                        f"<div style='color:{DC['text2']};font-size:.76em;line-height:1.45'>{label}</div></div>")

    return (f"<div style='background:linear-gradient(135deg,{DC['card']},{DC['elev']});"
            f"border:2px solid {narr_color};border-left:6px solid {narr_color};"
            f"border-radius:12px;padding:22px;margin:12px 0;box-shadow:0 6px 12px rgba(0,0,0,0.35)'>"
            f"<span style='font-size:1.3em;font-weight:700;color:{narr_color}'>🧠 THREAT NARRATIVE</span>"
            f"<div style='color:#f8fafc;font-size:1.05em;line-height:1.7;margin-top:14px'>{''.join(parts)}</div>"
            + (f"<div style='margin-top:12px'>{badges_html}</div>" if badges_html else "")
            + "</div>")


def _build_score_breakdown(R: dict) -> dict:
    sb = R.get('score_breakdown', {})
    score = R.get('score', 0)
    is_clean = score < 18
    real_sigs = filter_display_signals(R.get('signals', []))
    n_real = len(real_sigs)
    n_trust = len(R.get('trust_factors', []))
    n_esc = len(sb.get('cluster_contributions', []))
    n_damp = len(sb.get('dampening_contributions', []))

    pre_esc = sb.get('pre_escalation_score', 0)
    pre_dmp = sb.get('pre_dampen_score', 0)

    steps = [{'label': f"Detections ({n_real} signal{'s' if n_real != 1 else ''})",
              'value': f"{pre_esc:.0f} pts", 'color': DC['accent'],
              'tip': "Each detection adds risk based on severity and certainty."}]
    if n_esc > 0:
        steps.append({'label': f"Multi-attack bonus ({n_esc} combo{'s' if n_esc > 1 else ''})",
                      'value': f"+{(pre_dmp - pre_esc)*100:.0f} pts", 'color': DC['warn'],
                      'tip': "Multiple attack types together increase risk beyond their sum."})
    if n_damp > 0:
        steps.append({'label': f"Trust factors reduced score ({n_damp})",
                      'value': f"−{abs(pre_dmp*100 - score):.0f} pts", 'color': DC['ok'],
                      'tip': "Auth passes and clean indicators pull the score down."})
    steps.append({'label': "Final score", 'value': f"{score}/100",
                  'color': tc(R.get('threat_level', 'SAFE')), 'tip': ""})

    return {
        'steps': steps,
        'signal_contributions': sorted(sb.get('signal_contributions', []),
                                       key=lambda x: x.get('pts_added', 0), reverse=True),
        'cluster_contributions': sb.get('cluster_contributions', []),
        'dampening_contributions': sorted(sb.get('dampening_contributions', []),
                                          key=lambda x: x.get('pts_removed', 0), reverse=True),
        'n_real': n_real, 'n_trust': n_trust, 'n_esc': n_esc, 'is_clean': is_clean,
    }


def _build_reasoning_cards(R: dict) -> list:
    cards_out = []
    auth = R['auth']
    abuse = R.get('abuse_data', {})

    # Identity
    if auth.shadow_spoof and R.get('spoof'):
        cards_out.append(card('👤', 'Sender Identity',
            f"🚨 **Double deception** — display name + Return-Path routes to **{auth.rp_domain}**.",
            f"From: {auth.from_full[:70]}", DC['critical']))
    elif auth.shadow_spoof:
        cards_out.append(card('👤', 'Sender Identity',
            f"⚠️ **Return-Path mismatch** — from **{auth.from_domain}** but replies to **{auth.rp_domain}**.",
            f"From: {auth.from_full[:70]}", DC['critical']))
    elif R.get('spoof'):
        cards_out.append(card('👤', 'Sender Identity',
            f"🚨 **Display name spoof** — {R['spoof']}", f"Domain: {R.get('spoof_sd', '')}", DC['high']))
    else:
        cards_out.append(card('👤', 'Sender Identity',
            f"✅ **Sender identity consistent** — From and Return-Path align to **{auth.from_domain or 'unknown'}**.",
            f"From: {auth.from_full[:70]}", DC['ok']))

    # Auth
    if auth.spf == 'FAIL' and auth.dmarc == 'FAIL':
        ab, ac = "🚨 **Auth failure** — SPF unauthorized + DMARC violated.", DC['critical']
    elif auth.spf == 'FAIL':
        ab, ac = f"⚠️ **Unauthorized sender** — not in **{auth.from_domain}**'s SPF.", DC['critical']
    elif auth.spf == 'PASS' and auth.dkim == 'PASS' and auth.dmarc == 'PASS':
        ab, ac = "✅ **Full auth chain intact** — SPF, DKIM, DMARC all pass.", DC['ok']
    else:
        ab, ac = f"SPF: {auth.spf} | DKIM: {auth.dkim} | DMARC: {auth.dmarc}", DC['accent']
    if auth.gateway_trust:
        ab += f" 🛡️ Gateway **{auth.gateway_name}** pre-screened."
    det = ""
    if auth.live_verified:
        det = f"Live DNS — SPF: {auth.live_spf.get('status', '—')} | DMARC: {auth.live_dmarc.get('status', '—')}"
    cards_out.append(card('🔐', 'Authentication & DNS', ab, det, ac))

    # IP
    if auth.source_ip and abuse:
        ascore = abuse.get('abuseConfidenceScore', 0)
        if ascore >= 75:
            cards_out.append(card('🌐', 'Source IP',
                f"🚨 **High-risk IP** — {abuse.get('totalReports',0)} reports, {ascore}/100.",
                f"ISP: {abuse.get('isp', '—')}", DC['critical']))
        elif ascore >= 40:
            cards_out.append(card('🌐', 'Source IP',
                f"⚠️ **Elevated** — {abuse.get('totalReports',0)} reports ({ascore}/100).",
                f"ISP: {abuse.get('isp', '—')}", DC['high']))
        else:
            cards_out.append(card('🌐', 'Source IP',
                f"✅ **Clean** — {ascore}/100.", f"ISP: {abuse.get('isp', '—')}", DC['ok']))

    # Attachments
    real_att = [m for m in R.get('macros', []) if m.filename != '[Body]']
    if real_att:
        mb = sum(1 for m in real_att if m.mb_found)
        yr = sum(len(m.yara_matches) for m in real_att)
        if mb:
            fam = next((m.mb_family for m in real_att if m.mb_found), 'Unknown')
            cards_out.append(card('📎', 'Attachments', f"🚨 **Malware** — {fam}.",
                                  f"{len(real_att)} file(s)", DC['critical']))
        elif yr:
            cards_out.append(card('📎', 'Attachments', f"⚠️ **YARA** — {yr} rule(s) fired.",
                                  f"{len(real_att)} file(s)", DC['high']))
        else:
            cards_out.append(card('📎', 'Attachments', f"✅ **{len(real_att)} file(s) clean**.", "", DC['ok']))

    # BEC
    bec = R.get('bec')
    if bec and bec.score >= 0.25:
        bcol = DC['critical'] if bec.score >= 0.6 else DC['high']
        cards_out.append(card('🎯', 'BEC / Social Engineering', bec.summary,
                              f"Score: {bec.score:.0%} | {', '.join(bec.categories)}", bcol))

    return cards_out


# ═══════════════════════════════════════════════════════════════════════════════
# TAB 1: AUTH
# ═══════════════════════════════════════════════════════════════════════════════

def _build_auth_tab(R: dict) -> dict:
    auth = R['auth']
    _EXPLAIN = {
        'SPF': {'PASS': 'Server authorized by domain.', 'FAIL': 'Server NOT authorized.',
                'SOFTFAIL': 'Not fully authorized.', 'NONE': 'No SPF record.'},
        'DKIM': {'PASS': 'Signature verified — unmodified.', 'FAIL': 'Signature failed.',
                 'NONE': 'No DKIM signature.'},
        'DMARC': {'PASS': 'Domain policy enforced.', 'FAIL': 'Policy violated.',
                  'NONE': 'No DMARC policy.'},
    }
    protocols = []
    for proto, val in [('SPF', auth.spf), ('DKIM', auth.dkim), ('DMARC', auth.dmarc)]:
        color = DC['ok'] if val == 'PASS' else (DC['critical'] if val in ('FAIL', 'SOFTFAIL') else DC['text2'])
        icon = '✅' if val == 'PASS' else ('🚨' if val in ('FAIL', 'SOFTFAIL') else 'ℹ️')
        protocols.append({
            'proto': proto, 'val': val, 'color': color, 'icon': icon,
            'explain': _EXPLAIN.get(proto, {}).get(val, ''),
        })

    details = [d for d in auth.details
               if not any(d.lower().startswith(p) for p in ('spf', 'dkim', 'dmarc', 'source ip', 'hop'))]

    return {
        'spf': auth.spf, 'dkim': auth.dkim, 'dmarc': auth.dmarc,
        'hop_count': str(auth.hop_count), 'protocols': protocols,
        'source_ip': auth.source_ip, 'from_full': auth.from_full[:90],
        'from_domain': auth.from_domain, 'rp_domain': auth.rp_domain,
        'gateway_trust': auth.gateway_trust, 'gateway_name': auth.gateway_name,
        'hop_anomaly': auth.hop_anomaly, 'hop_delays': auth.hop_delays,
        'spoof': R.get('spoof', ''),
        'anomalies': R.get('anomalies', []),
        'extra_details': details,
        'abuse': R.get('abuse_data', {}),
        'dnsbl_sigs': [s for s in R.get('signals', []) if s.name in ('dnsbl_listed', 'dnsbl_pbl')],
        'mx_sigs': [s for s in R.get('signals', []) if s.name == 'no_mx_record'],
    }


# ═══════════════════════════════════════════════════════════════════════════════
# TAB 2: URLS
# ═══════════════════════════════════════════════════════════════════════════════

def _classify_observable(o) -> tuple:
    tl = o.vt.threat_level if o.vt else 'UNKNOWN'
    di = o.vt.domain_intel if o.vt else None
    try:
        dom = url_host(o.value) if o.type == 'url' else o.value.lower()
        gw = is_tracking_domain(dom)
    except Exception:
        gw = False
    if tl in ('CRITICAL', 'MALICIOUS'):
        return 'THREAT', tc(tl), ti(tl)
    if tl == 'SUSPICIOUS':
        return 'SUSPICIOUS', DC['warn'], '⚠️'
    if tl == 'UNKNOWN' and gw:
        return 'GATEWAY', DC['accent'], '🛡️'
    if tl == 'UNKNOWN' and di and di.trusted:
        return 'TRUSTED', DC['ok'], '✅'
    if tl == 'UNKNOWN' and di and di.typosquat:
        return 'SUSPICIOUS', DC['warn'], '⚠️'
    if tl == 'UNKNOWN':
        return 'UNKNOWN', DC['unknown'], '❓'
    return 'CLEAN', DC['ok'], '✅'


def _build_urls_tab(R: dict) -> dict:
    mismatches = R.get('link_mismatches', [])
    real_mm = [m for m in mismatches if not m.is_tracking]
    track_mm = [m for m in mismatches if m.is_tracking]

    seen = set()
    unique_mm = []
    for m in real_mm:
        pair = (m.display_domain, m.href_domain)
        if pair not in seen:
            seen.add(pair)
            unique_mm.append(m)

    seen_gw = set()
    unique_gw = []
    for m in track_mm:
        if m.href_domain not in seen_gw:
            seen_gw.add(m.href_domain)
            unique_gw.append(m)

    obs = R.get('observables', [])
    vt_obs = [o for o in obs if o.vt]

    classified = []
    for o in vt_obs:
        level, color, icon = _classify_observable(o)
        classified.append({'obs': o, 'level': level, 'color': color, 'icon': icon})

    return {
        'real_mismatches': unique_mm,
        'tracking_mismatches': unique_gw,
        'total_real_mm': len(real_mm),
        'threats':  [c for c in classified if c['level'] in ('THREAT', 'SUSPICIOUS')],
        'unknowns': [c for c in classified if c['level'] == 'UNKNOWN'],
        'gateways': [c for c in classified if c['level'] == 'GATEWAY'],
        'clean':    [c for c in classified if c['level'] in ('CLEAN', 'TRUSTED')],
        'total_scanned': len(vt_obs),
    }


# ═══════════════════════════════════════════════════════════════════════════════
# TABS 3-8
# ═══════════════════════════════════════════════════════════════════════════════

def _build_attachments_tab(R: dict) -> dict:
    macros = R.get('macros', [])
    real = [m for m in macros if m.filename != '[Body]']
    cards = []
    for m in real:
        eff_score = m.risk_score
        if (m.verdict == 'SUSPICIOUS' or m.has_macros) and eff_score < 30:
            eff_score = 30
        color = DC['critical'] if eff_score >= 70 else (DC['high'] if eff_score >= 40 else (DC['warn'] if eff_score >= 30 else DC['ok']))
        icon = "🔴" if eff_score >= 70 else ("🟡" if eff_score >= 40 else ("🟠" if eff_score >= 30 else "🟢"))
        cards.append({
            'filename': m.filename, 'file_type': m.file_type, 'risk_score': m.risk_score,
            'eff_score': eff_score, 'verdict': m.verdict or 'SAFE', 'color': color, 'icon': icon,
            'sha256': m.sha256, 'mb_found': m.mb_found, 'mb_family': m.mb_family,
            'details': m.details, 'embedded_uris': getattr(m, 'embedded_uris', []) or getattr(m, 'pdf_uris', []),
        })
    return {'cards': cards, 'risks': R.get('attachment_risks', [])}


def _build_yara_tab(R: dict) -> dict:
    hits = [(m.filename, y) for m in R.get('macros', []) for y in m.yara_matches]
    threat_hits = [(fn, y) for fn, y in hits if not y.get('enrichment')]
    sev_counts = {}
    for _, y in threat_hits:
        sev_counts[y['severity']] = sev_counts.get(y['severity'], 0) + 1

    from collections import defaultdict
    by_file = defaultdict(list)
    for fn, y in hits:
        by_file[fn].append(y)

    return {
        'total': len(hits), 'threat_count': len(threat_hits),
        'sev_counts': sev_counts, 'by_file': dict(by_file),
    }


def _build_images_tab(R: dict) -> dict:
    images = R.get('images', [])
    cards = []
    for img in images:
        has_threat = img.has_steg
        has_qr = bool(img.qr_links)
        is_tracker = any('tracking' in f.lower() or '<=2x2' in f for f in img.findings)
        if has_threat:
            color, verdict, detail = DC['critical'], "🚨 SUSPICIOUS", "Steganography detected"
        elif has_qr:
            color, verdict, detail = DC['warn'], "⚠️ QR CODE", "QR code with URL(s)"
        elif is_tracker:
            color, verdict, detail = DC['text2'], "📡 TRACKER", "Tracking pixel"
        else:
            color, verdict, detail = DC['ok'], "✅ CLEAN", "No anomalies"
        cards.append({
            'filename': img.filename, 'fmt': img.fmt or 'Unknown', 'size': img.size,
            'color': color, 'verdict': verdict, 'detail': detail,
            'data': img.data, 'findings': img.findings, 'ocr_text': img.ocr_text,
            'qr_links': img.qr_links,
        })
    return {'cards': cards}


def _build_findings_tab(R: dict) -> dict:
    display_sigs = filter_display_signals(R.get('signals', []))
    sorted_sigs = sorted(display_sigs, key=lambda x: x.probability * x.confidence, reverse=True)
    sig_rows = [{
        'Tier': f"T{s.tier}", 'Category': s.category, 'Signal': s.title,
        'Probability': f"{s.probability:.0%}", 'Confidence': f"{s.confidence:.0%}",
        'Impact': f"{s.probability * s.confidence:.0%}", 'Detail': s.detail[:80],
    } for s in sorted_sigs]

    tf_rows = [{
        'Factor': tf.name, 'Strength': f"{tf.strength:.0%}",
        'Confidence': f"{tf.confidence:.0%}", 'Description': tf.description,
    } for tf in R.get('trust_factors', [])]

    return {'signals_df': sig_rows, 'trust_df': tf_rows}


def _build_export_tab(R: dict) -> dict:
    from .reports import generate_text_report, generate_analyst_report, build_soar_json
    return {
        'text_report': _safe(lambda: generate_text_report(R), "Report generation failed"),
        'analyst_report': _safe(lambda: generate_analyst_report(R), "Report generation failed"),
        'soar_json': _safe(lambda: json.dumps(build_soar_json(R, ''), indent=2, default=str),
                           '{"error": "generation failed"}'),
    }


def _build_soc_tab(R: dict) -> dict:
    signals = R.get('signals', [])
    seen = set()
    mitre = []
    for s in signals:
        if s.probability * s.confidence < 0.04:
            continue
        tech = MITRE_MAP.get(s.name)
        if tech and tech[0] not in seen:
            seen.add(tech[0])
            mitre.append({'id': tech[0], 'name': tech[1], 'tactic': tech[2],
                          'triggered_by': s.name, 'signal_title': s.title})

    auth = R['auth']
    obs = R.get('observables', [])
    iocs = {
        'ips': sorted({o.value for o in obs if o.type == 'ip'} | ({auth.source_ip} if auth.source_ip else set())),
        'domains': sorted({o.value for o in obs if o.type == 'domain'}),
        'urls': sorted({o.value for o in obs if o.type == 'url'}),
        'hashes': R.get('hashes', {}),
    }
    return {'mitre': mitre, 'iocs': iocs, 'hashes': R.get('hashes', {})}
