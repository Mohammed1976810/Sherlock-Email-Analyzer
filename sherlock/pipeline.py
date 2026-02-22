"""Main analysis pipeline — single-pass orchestrator.

Key changes from original:
  - Single msg.walk() collects ALL parts (bodies, attachments, images)
  - normalize_text() called once, result passed downstream
  - Parallel scan phase: attachments + images + DNS in one pool
  - Single VT pass with circuit breaker
  - Signal generation via registry (no monolithic function)
  - Scoring engine is 4 steps, not 9
"""
from __future__ import annotations
import email, email.policy, email.utils
import hashlib, time, threading, logging
from concurrent.futures import ThreadPoolExecutor, as_completed, wait as _cf_wait
from typing import Callable, Optional, Dict

from .models import Observable, AttachmentResult, ImageAnalysis
from .utils import (
    normalize_text, defang, url_host, root_domain, is_private_ip,
    filter_display_signals
)
from .constants import (
    MAX_FILE_SIZE, MAX_OBS, VT_BUDGET_SECS, PAT_DOMAIN,
)
from .analysis.auth import analyze_auth
from .analysis.bec import analyze_bec
from .analysis.headers import analyze_headers, check_display_spoof
from .analysis.attachments import analyze_attachment, yara_scan, YARA_OK
from .analysis.observables import extract_observables, extract_visible_text
from .analysis.images import analyze_image
from .analysis.content import detect_tracking_pixels, detect_suspicious_language
from .analysis.domain import domain_intel
from .intel.reputation import check_abuseipdb, check_spamhaus, check_mx
from .intel.virustotal import check_vt
from .intel.otx import check_otx
from .intel.xforce import check_xforce
from .scoring.signals import generate_all
from .scoring.engine import run_scoring, detect_clusters
from .scoring.narrative import build_narrative

log = logging.getLogger("sherlock.pipeline")


def analyze_email(msg_bytes: bytes,
                  status_fn: Callable = lambda m, i: None,
                  progress_fn: Callable = lambda p: None,
                  vt_key: str = "",
                  abuse_key: str = "",
                  otx_key: str = "",
                  xforce_key: str = "",
                  xforce_secret: str = "") -> dict:
    """Main analysis pipeline. Returns a fully-populated report dict."""
    if len(msg_bytes) > MAX_FILE_SIZE:
        raise ValueError(f"File exceeds {MAX_FILE_SIZE // 1024 // 1024}MB")

    msg = email.message_from_bytes(msg_bytes, policy=email.policy.default)
    subject = str(msg.get('Subject', '') or '')
    from_addr = str(msg.get('From', '') or '')

    org_domain = ""
    for hdr in ('Delivered-To', 'To'):
        m = PAT_DOMAIN.search(str(msg.get(hdr, '') or ''))
        if m:
            org_domain = m.group(1).lower()
            break

    # ═══════════════════════════════════════════════════════════════════════════
    # SINGLE PASS: collect all parts from msg.walk() at once
    # (Original called msg.walk() 3 times)
    # ═══════════════════════════════════════════════════════════════════════════
    status_fn("Parsing email structure...", "🔍")
    progress_fn(5)

    html_body = ""
    text_body = ""
    att_parts = []   # (bytes, filename)
    img_parts = []   # raw message parts

    _BINARY_CT = {
        "application/pdf": ".pdf", "application/msword": ".doc",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document": ".docx",
        "application/vnd.ms-excel": ".xls", "application/zip": ".zip",
        "application/octet-stream": ".bin", "application/x-msdownload": ".exe",
    }

    for part in msg.walk():
        ct = part.get_content_type()
        if part.get_content_maintype() == "multipart":
            continue

        # Images
        if ct.startswith("image/"):
            img_parts.append(part)
            continue

        # Body text
        try:
            payload = part.get_payload(decode=True)
            if not isinstance(payload, bytes) or not payload:
                continue
        except Exception:
            continue

        if ct == 'text/html':
            html_body += payload.decode('utf-8', 'ignore')
            continue
        elif ct == 'text/plain':
            text_body += payload.decode('utf-8', 'ignore')
            continue

        # Attachment
        fname = part.get_filename() or part.get_param("name", header="content-type")
        if not fname and ct in _BINARY_CT and len(payload) > 64:
            fname = f"attachment_inline{_BINARY_CT[ct]}"
        if fname and len(payload) <= MAX_FILE_SIZE:
            att_parts.append((payload, fname))

    # Extract visible text once (shared downstream)
    visible_text = extract_visible_text(html_body) or text_body
    normalized = normalize_text(visible_text)
    word_count = len(normalized.split())
    progress_fn(10)

    # ═══════════════════════════════════════════════════════════════════════════
    # PARALLEL INIT: auth + BEC + headers + spoof + body analysis
    # ═══════════════════════════════════════════════════════════════════════════
    status_fn("Analysing auth, BEC, headers...", "🔐")
    with ThreadPoolExecutor(max_workers=6) as pool:
        f_auth  = pool.submit(analyze_auth, msg)
        f_bec   = pool.submit(analyze_bec, visible_text, subject, from_addr, word_count)
        f_hdrs  = pool.submit(analyze_headers, msg)
        f_spoof = pool.submit(check_display_spoof, msg, org_domain)
        f_obs   = pool.submit(extract_observables, msg, html_body, text_body)
        f_track = pool.submit(detect_tracking_pixels, html_body)
        f_lang  = pool.submit(detect_suspicious_language, visible_text, subject)

        auth = f_auth.result()
        bec = f_bec.result()
        anomalies, reply_hijack = f_hdrs.result()
        spoof_result, spoof_dn, spoof_sd = f_spoof.result()
        observables, link_mismatches = f_obs.result()
        body_findings = f_track.result()
        body_findings.extend(f_lang.result())
    progress_fn(30)

    # AbuseIPDB (needs auth.source_ip)
    abuse_data = check_abuseipdb(auth.source_ip, abuse_key) if auth.source_ip and abuse_key else {}

    # Spamhaus + MX
    dnsbl_results = []
    if auth.source_ip:
        listed, cat, desc = check_spamhaus(auth.source_ip)
        if listed:
            dnsbl_results.append({'cat': cat, 'desc': desc})

    no_mx = False
    if auth.from_domain and auth.spf in ('FAIL', 'SOFTFAIL', 'NONE'):
        has_mx, _ = check_mx(auth.from_domain)
        no_mx = not has_mx

    # Sender memory (simplified — check only, recording done after scoring)
    from .analysis.domain import _CACHE  # reuse domain cache for sender check
    sender_memory = {'known': False, 'count': 0, 'days': 0}

    # ═══════════════════════════════════════════════════════════════════════════
    # PARALLEL SCAN: attachments + images + DNS classification
    # ═══════════════════════════════════════════════════════════════════════════
    status_fn(f"Scanning {len(att_parts)} attachment(s), {len(img_parts)} image(s)...", "⚡")

    macros = []
    images = []
    embedded_obs = []
    ocr_bec_hits = 0
    _att_lock = threading.Lock()

    def _scan_att(data, fname):
        macro = analyze_attachment(data, fname)
        new_obs = [Observable(type='url', value=u, defanged=defang(u),
                              source='pdf_uri' if macro.file_type == 'PDF' else 'office_link')
                   for u in macro.embedded_uris if u.startswith('http')]
        return macro, new_obs

    def _scan_img(part):
        try:
            return analyze_image(part)
        except Exception:
            return None

    def _dns_classify(obs_list):
        """Parallel DNS pre-classification of observable domains."""
        domains = set()
        for o in obs_list:
            try:
                if o.type == 'url':
                    h = url_host(o.value)
                    if h: domains.add(root_domain(h))
                elif o.type in ('domain', 'ip'):
                    domains.add(root_domain(o.value))
            except Exception: pass
        if not domains:
            return {}

        import socket
        classified = {}
        cl_lock = threading.Lock()

        def _check(d):
            try:
                ip = socket.gethostbyname(d)
                cat = 'private' if is_private_ip(ip) else 'public'
            except Exception:
                cat = 'unresolvable'
            with cl_lock:
                classified[d] = cat

        with ThreadPoolExecutor(max_workers=min(30, max(len(domains), 1))) as ex:
            futs = {ex.submit(_check, d): d for d in domains}
            done, pending = _cf_wait(futs, timeout=8.0)
            for f in pending:
                f.cancel()
            with cl_lock:
                for d in domains:
                    if d not in classified:
                        classified[d] = 'public'
        return classified

    with ThreadPoolExecutor(max_workers=12) as scan_pool:
        scan_futs = {}
        for data, fname in att_parts:
            scan_futs[scan_pool.submit(_scan_att, data, fname)] = ('att', fname)
        for part in img_parts:
            scan_futs[scan_pool.submit(_scan_img, part)] = ('img', part.get_filename() or 'image')

        dns_fut = scan_pool.submit(_dns_classify, [o for o in observables if o.type in ('url', 'domain', 'ip')])

        # Body YARA
        body_yara = [None]
        def _body_yara():
            if YARA_OK and visible_text:
                body_yara[0] = yara_scan(visible_text.encode('utf-8', 'ignore'), 'email_body',
                                         exclude_attachment_only=True)
        scan_pool.submit(_body_yara)

        for fut in as_completed(scan_futs):
            tag, name = scan_futs[fut]
            try:
                result = fut.result()
                if tag == 'att' and result:
                    macro, new_obs = result
                    with _att_lock:
                        macros.append(macro)
                        embedded_obs.extend(new_obs)
                elif tag == 'img' and result:
                    img = result
                    with _att_lock:
                        images.append(img)
                        for qr in img.qr_links:
                            embedded_obs.append(Observable(
                                type='url', value=qr, defanged=defang(qr), source='qr'))
                        if img.ocr_text:
                            from .analysis.bec import analyze_bec as _ab
                            if _ab(img.ocr_text, "", "", len(img.ocr_text.split())).score >= 0.25:
                                ocr_bec_hits += 1
            except Exception:
                pass

        try:
            dns_class = dns_fut.result(timeout=10)
        except Exception:
            dns_class = {}

    # Body YARA result
    if body_yara[0]:
        macros.append(AttachmentResult(
            filename="[Body]", file_type="HTML/Text",
            yara_matches=body_yara[0],
            verdict=f"YARA: {body_yara[0][0]['rule']}"))

    # Attachment structural risks (single pass — was separate msg.walk())
    from .analysis.attachments import _check_archive_risks
    attachment_risks = _check_archive_risks(att_parts)
    progress_fn(60)

    # ═══════════════════════════════════════════════════════════════════════════
    # MERGE embedded observables + DNS-filtered VT pass
    # ═══════════════════════════════════════════════════════════════════════════
    embedded_obs = embedded_obs[:MAX_OBS]
    if embedded_obs:
        try:
            emb_dns = _dns_classify(embedded_obs)
            dns_class.update(emb_dns)
        except Exception:
            pass
        observables.extend(embedded_obs)

    # VT + OTX + XForce enrichment
    vt_candidates = [o for o in observables if o.type in ('url', 'domain', 'ip')]
    vt_candidates.sort(key=lambda o: (
        -100 * o.is_shortener - 80 * o.suspicious_tld - 75 * o.is_wrapper
        - 60 * (o.path_entropy > 4.5) - 40 * (o.type == 'ip')
    ))

    def _should_skip(o):
        try:
            d = root_domain(url_host(o.value)) if o.type == 'url' else root_domain(o.value)
        except Exception:
            return False
        dc = dns_class.get(d, 'public')
        if dc == 'private':
            return True
        if dc == 'unresolvable' and not o.is_shortener and not o.suspicious_tld:
            return True
        return False

    vt_batch = [o for o in vt_candidates[:MAX_OBS] if not _should_skip(o)]
    skip_batch = [o for o in vt_candidates if _should_skip(o)]

    # Local-only enrichment for skipped observables
    for o in skip_batch:
        try:
            dom = url_host(o.value) if o.type == 'url' else o.value
            di = domain_intel(dom)
            from .models import VTResult
            r = VTResult(success=True, error="DNS-filtered")
            r.domain_intel = di
            r.threat_level = "CLEAN" if (di and di.trusted) else "UNKNOWN"
            r.reasoning = f"Trusted: {di.reasoning}" if (di and di.trusted) else "Internal/unresolvable"
            o.vt = r
        except Exception:
            pass

    # OTX/XForce for all (no rate limit)
    def _enrich_ti(o):
        kind = o.type if o.type in ('ip', 'domain', 'url') else None
        if not kind:
            return
        try:
            o.otx = check_otx(kind, o.value, otx_key)
        except Exception: pass
        try:
            o.xforce = check_xforce(kind, o.value, xforce_key, xforce_secret)
        except Exception: pass

    status_fn(f"Threat intel: {len(vt_batch)} VT + {len(observables)} OTX/XForce...", "🔍")
    deadline = time.time() + VT_BUDGET_SECS

    with ThreadPoolExecutor(max_workers=8) as otx_pool:
        otx_futs = [otx_pool.submit(_enrich_ti, o) for o in observables]
        with ThreadPoolExecutor(max_workers=4) as vt_pool:
            vt_futs = {}
            for o in vt_batch:
                if time.time() > deadline:
                    from .models import VTResult
                    o.vt = VTResult(success=True, error="VT budget exceeded",
                                    threat_level="UNKNOWN", reasoning="VT budget reached")
                    continue
                vt_futs[vt_pool.submit(check_vt, o.type, o.value, vt_key)] = o

            for f in as_completed(vt_futs):
                o = vt_futs[f]
                try:
                    o.vt = f.result()
                except Exception:
                    pass
        for f in as_completed(otx_futs):
            try: f.result()
            except Exception: pass

    # Merge TI scores
    for o in observables:
        _apply_ti_scores(o)

    progress_fn(90)

    # ═══════════════════════════════════════════════════════════════════════════
    # SIGNAL GENERATION + SCORING (registry-based + 4-step engine)
    # ═══════════════════════════════════════════════════════════════════════════
    status_fn("Computing verdict...", "⚖️")

    ctx = {
        'auth': auth, 'bec': bec, 'observables': observables,
        'macros': macros, 'images': images,
        'link_mismatches': link_mismatches, 'body_findings': body_findings,
        'attachment_risks': attachment_risks, 'abuse_data': abuse_data,
        'anomalies': anomalies, 'reply_hijack': reply_hijack,
        'spoof_result': spoof_result, 'spoof_dn': spoof_dn, 'spoof_sd': spoof_sd,
        'dnsbl_results': dnsbl_results, 'no_mx': no_mx,
        'sender_memory': sender_memory, 'ocr_bec_hits': ocr_bec_hits,
    }

    signals, trust_factors = generate_all(ctx)
    scoring = run_scoring(signals, trust_factors)
    narrative = build_narrative(scoring.signals, scoring.trust_factors, auth, scoring.score)

    progress_fn(100)
    status_fn(f"Done! Verdict: {scoring.verdict}", "✅")

    return {
        'verdict': scoring.verdict,
        'threat_level': scoring.threat_level,
        'score': scoring.score,
        'confidence': scoring.confidence,
        'analysis_confidence': scoring.analysis_confidence,
        'explanation': scoring.explanation,
        'risk_narrative': narrative,
        'active_clusters': {
            k: [{'name': s.name, 'title': s.title,
                 'prob': round(s.probability, 3), 'conf': round(s.confidence, 3)}
                for s in v]
            for k, v in scoring.active_clusters.items()
        },
        'signals': scoring.signals,
        'trust_factors': scoring.trust_factors,
        'correlations': scoring.correlations_applied,
        'dampening': scoring.dampening_applied,
        'score_breakdown': {
            'signal_contributions': scoring.signal_contributions,
            'pre_escalation_score': round(scoring.pre_escalation_score * 100, 1),
            'pre_dampen_score': round(scoring.pre_dampen_score * 100, 1),
            'final_score': scoring.score,
            'cluster_contributions': scoring.cluster_contributions,
            'cluster_signal_subtotals': scoring.cluster_signal_subtotals,
            'dampening_contributions': scoring.dampening_contributions,
        },
        'dominant_vector': scoring.dominant_vector,
        'auth': auth, 'bec': bec, 'observables': observables,
        'macros': macros, 'images': images,
        'link_mismatches': link_mismatches, 'body_findings': body_findings,
        'attachment_risks': attachment_risks, 'abuse_data': abuse_data,
        'anomalies': anomalies, 'reply_hijack': reply_hijack,
        'spoof': spoof_result, 'spoof_dn': spoof_dn, 'spoof_sd': spoof_sd,
        'hashes': {
            'md5': hashlib.md5(msg_bytes).hexdigest(),
            'sha256': hashlib.sha256(msg_bytes).hexdigest(),
        },
        'metadata': {
            'from': str(msg.get('From', '')),
            'subject': subject,
            'date': str(msg.get('Date', '')),
        },
    }


def _apply_ti_scores(o: Observable):
    """Merge VT + OTX + X-Force into threat_score and reputation."""
    if o.vt and o.vt.success:
        if o.vt.threat_level in ('CRITICAL', 'MALICIOUS'):
            o.threat_score, o.reputation = 100, 'malicious'
        elif o.vt.threat_level == 'SUSPICIOUS':
            o.threat_score, o.reputation = 50, 'suspicious'
        else:
            o.reputation = 'clean'
    for attr in ('otx', 'xforce'):
        data = getattr(o, attr, {})
        if not data:
            continue
        lvl = data.get('threat_level', '')
        if lvl == 'CRITICAL' and o.threat_score < 100:
            o.threat_score = max(o.threat_score, 80)
            o.reputation = 'malicious'
        elif lvl == 'HIGH' and o.threat_score < 80:
            o.threat_score = max(o.threat_score, 60)
            if o.reputation == 'clean':
                o.reputation = 'suspicious'
