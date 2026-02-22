"""Report generation — text, analyst, PDF, SOAR JSON.

Called during prepare_display(), not during rendering.
"""
from __future__ import annotations
import re, json, io
from datetime import datetime, timezone
from .utils import esc, filter_display_signals
from .constants import MITRE_MAP

try:
    from reportlab.lib.pagesizes import letter
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    PDF_OK = True
except ImportError:
    PDF_OK = False


def generate_text_report(R: dict) -> str:
    sep = "=" * 90
    L = [sep, "SHERLOCK FORENSIC REPORT", sep,
         f"Date: {datetime.now():%Y-%m-%d %H:%M:%S}",
         f"MD5: {R['hashes']['md5']}  SHA256: {R['hashes']['sha256']}", "",
         f"VERDICT: {R['verdict']}  |  Score: {R['score']}/100  |  "
         f"Threat: {R['threat_level']}  |  Confidence: {R.get('confidence', 0)}%", ""]

    narrative = R.get('risk_narrative', '')
    if narrative:
        L += [sep, "THREAT NARRATIVE", sep, re.sub(r'\*\*(.+?)\*\*', r'\1', narrative), ""]

    L += [f"Engine: {R.get('explanation', '')}", ""]

    L += [sep, "SIGNALS", sep]
    for s in sorted(filter_display_signals(R.get('signals', [])),
                    key=lambda x: x.probability * x.confidence, reverse=True):
        L.append(f"  [T{s.tier}/{s.category}] {s.title}  p={s.probability:.0%} c={s.confidence:.0%}")
        if s.detail:
            L.append(f"    {s.detail}")

    if R.get('trust_factors'):
        L += ["", sep, "TRUST FACTORS", sep]
        for t in R['trust_factors']:
            L.append(f"  {t.name}: {t.strength:.0%} — {t.description}")

    auth = R['auth']
    L += ["", sep, "AUTHENTICATION", sep,
          f"SPF: {auth.spf}  DKIM: {auth.dkim}  DMARC: {auth.dmarc}",
          f"Source IP: {auth.source_ip or '—'}  Hops: {auth.hop_count}"]

    L += ["", sep, "ATTACHMENTS", sep]
    for m in R.get('macros', []):
        if m.filename == '[Body]':
            continue
        L.append(f"  {m.filename}: {m.file_type} | Risk {m.risk_score}/100 | {m.verdict}")
        if m.mb_found:
            L.append(f"    MALWARE: {m.mb_family}")
    L.append(sep)
    return '\n'.join(L)


def generate_analyst_report(R: dict) -> str:
    auth = R['auth']
    meta = R.get('metadata', {})
    score = R['score']

    auth_parts = []
    for proto, val in [('SPF', auth.spf), ('DKIM', auth.dkim), ('DMARC', auth.dmarc)]:
        if val == 'PASS':
            auth_parts.append(proto)
    auth_line = (f"Passes {' and '.join(auth_parts)} checks." if auth_parts
                 else "No authentication passes.")

    real_att = [m for m in R.get('macros', []) if m.filename != '[Body]']
    if not real_att:
        att_line = "No attachments found."
    else:
        statuses = []
        for m in real_att:
            s = "MALWARE" if m.mb_found else ("SUSPICIOUS" if m.has_macros or m.yara_matches else "Clean")
            statuses.append(f"`{m.filename}` ({s})")
        att_line = f"{len(real_att)} attachment(s): {', '.join(statuses)}."

    url_obs = [o for o in R.get('observables', []) if o.type in ('url', 'domain')]
    threats = [o for o in url_obs if o.vt and o.vt.threat_level in ('CRITICAL', 'MALICIOUS')]
    if not url_obs:
        link_line = "No external links detected."
    elif threats:
        link_line = f"{len(url_obs)} link(s) detected. ALERT: {len(threats)} confirmed malicious."
    else:
        link_line = f"{len(url_obs)} link(s) detected. All scanned links appear legitimate."

    _RECS = [(65, "BLOCK / QUARANTINE immediately."), (40, "Quarantine and notify recipient."),
             (18, "Hold for analyst review."), (0, "Recommend release.")]
    rec = next(r for t, r in _RECS if score >= t)

    return '\n'.join([
        "Header & Path", "",
        f"* From: `{meta.get('from', 'Unknown')[:60]}`",
        f"* Domain: `{auth.from_domain or 'Unknown'}`", "",
        "Technical Authentication & Analysis", "",
        f"* Authentication: {auth_line}",
        f"* Source IP: `{auth.source_ip or 'Unknown'}`"
        + (f" via {auth.gateway_name}" if auth.gateway_name else ""),
        f"* Verdict: {R['verdict']} (score: {score}/100)", "",
        "Attachment & Links", "",
        f"* {att_line}",
        f"* {link_line}", "",
        f"* Recommendation: {rec}",
    ])


def build_soar_json(R: dict, case_id: str = "") -> dict:
    auth = R['auth']
    meta = R.get('metadata', {})
    score = R['score']

    _ACTIONS = [(65, "QUARANTINE"), (40, "HOLD_FOR_REVIEW"), (18, "DELIVER_WITH_WARNING"), (0, "RELEASE")]
    action = next(a for t, a in _ACTIONS if score >= t)

    sig_list = [
        {'name': s.name, 'title': s.title, 'category': s.category, 'tier': s.tier,
         'probability': round(s.probability, 3), 'confidence': round(s.confidence, 3),
         'impact': round(s.probability * s.confidence, 3), 'detail': s.detail, 'evidence': s.evidence or ""}
        for s in sorted(filter_display_signals(R.get('signals', [])),
                        key=lambda x: x.probability * x.confidence, reverse=True)
    ][:20]

    return {
        'schema_version': '2.0', 'tool': 'Sherlock Forensic Email Analyzer',
        'case_id': case_id, 'file_id': R['hashes']['md5'], 'sha256': R['hashes']['sha256'],
        'submitted_at': datetime.now(timezone.utc).isoformat(),
        'verdict': {
            'classification': R['verdict'], 'threat_level': R['threat_level'],
            'score': score, 'confidence': R.get('confidence', 0), 'action': action,
            'risk_narrative': R.get('risk_narrative', ''),
        },
        'sender': {
            'from': meta.get('from', ''), 'subject': meta.get('subject', ''),
            'from_domain': auth.from_domain, 'source_ip': auth.source_ip,
        },
        'authentication': {
            'spf': auth.spf, 'dkim': auth.dkim, 'dmarc': auth.dmarc,
            'shadow_spoof': auth.shadow_spoof,
        },
        'signals': sig_list,
        'trust_factors': [{'name': tf.name, 'strength': round(tf.strength, 3),
                           'description': tf.description} for tf in R.get('trust_factors', [])],
    }


def generate_pdf(text: str):
    if not PDF_OK:
        return None
    try:
        buf = io.BytesIO()
        doc = SimpleDocTemplate(buf, pagesize=letter)
        styles = getSampleStyleSheet()
        cs = ParagraphStyle('Code', parent=styles['Normal'], fontName='Courier', fontSize=8, leading=10)
        story = [Paragraph("Sherlock Report", styles['Heading1']), Spacer(1, 12)]
        for line in text.split('\n'):
            if '===' in line:
                story.append(Spacer(1, 6))
            elif line.strip():
                story.append(Paragraph(esc(line).replace(' ', '&nbsp;'), cs))
            else:
                story.append(Spacer(1, 4))
        doc.build(story)
        buf.seek(0)
        return buf
    except Exception:
        return None
