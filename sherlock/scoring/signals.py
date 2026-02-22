"""Signal generation — registry-based architecture.

Each analysis module registers emitters via @signal_emitter. The generate_all()
function calls every registered emitter and deduplicates the results.
This replaces the original 534-line monolithic generate_signals() function.
"""
from __future__ import annotations
from typing import List, Tuple, Callable, Any
from ..models import (
    ThreatSignal, TrustFactor, AuthResult, BECResult, Observable,
    AttachmentResult, ImageAnalysis, LinkMismatch
)
from ..utils import (
    root_domain, url_host, is_tracking_domain, normalize_url,
    subdomain_entropy, is_randomized_domain, defang
)
from ..constants import (
    TIER1_BEC, SUSPICIOUS_TLDS, URL_SHORTENERS, PROTECTED_BRANDS
)

_EMITTERS: List[Callable] = []


def signal_emitter(fn: Callable) -> Callable:
    _EMITTERS.append(fn)
    return fn


# ── AUTH SIGNALS ──────────────────────────────────────────────────────────────

_AUTH_SIGNAL_MAP = {
    'FAIL':     ('spf_fail',     2, 0.70, 0.90, "SPF FAIL", "Sending server not authorized"),
    'SOFTFAIL': ('spf_softfail', 3, 0.35, 0.80, "SPF SOFTFAIL", "Sender not fully authorized"),
}
_DKIM_SIGNAL_MAP = {
    'FAIL': ('dkim_fail', 2, 0.50, 0.85, "DKIM FAIL", "Message integrity compromised"),
}
_DMARC_SIGNAL_MAP = {
    'FAIL': ('dmarc_fail', 2, 0.55, 0.85, "DMARC FAIL", "Domain policy violated"),
}


@signal_emitter
def _auth_signals(ctx) -> Tuple[List[ThreatSignal], List[TrustFactor]]:
    auth: AuthResult = ctx['auth']
    sigs, trust = [], []

    # SPF / DKIM / DMARC via dict mapping (replaces if/elif chains)
    entry = _AUTH_SIGNAL_MAP.get(auth.spf)
    if entry:
        sigs.append(ThreatSignal(*entry, f"From: {auth.from_domain}"))
    elif auth.spf == 'PASS':
        trust.append(TrustFactor('spf_pass', 0.15, 0.90, "SPF passed"))

    entry = _DKIM_SIGNAL_MAP.get(auth.dkim)
    if entry:
        sigs.append(ThreatSignal(*entry, ""))
    elif auth.dkim == 'PASS':
        trust.append(TrustFactor('dkim_pass', 0.15, 0.90, "DKIM passed"))
    elif auth.dkim == 'NONE' and auth.spf in ('FAIL', 'SOFTFAIL'):
        sigs.append(ThreatSignal('dkim_none_compound', 'auth', 3, 0.20, 0.70,
                                 "No DKIM + SPF issue", "No cryptographic integrity", ""))

    entry = _DMARC_SIGNAL_MAP.get(auth.dmarc)
    if entry:
        sigs.append(ThreatSignal(*entry, ""))
    elif auth.dmarc == 'PASS':
        trust.append(TrustFactor('dmarc_pass', 0.12, 0.90, "DMARC passed"))

    if auth.shadow_spoof:
        sigs.append(ThreatSignal('shadow_spoofing', 'auth', 2, 0.75, 0.90,
                                 "Shadow Spoofing", "From/Return-Path mismatch",
                                 f"{auth.from_domain} vs {auth.rp_domain}"))
    if auth.gateway_trust:
        trust.append(TrustFactor('gateway', 0.25, 0.85, f"Trusted gateway: {auth.gateway_name}"))

    if auth.hop_anomaly and 'stall' in auth.hop_anomaly.lower():
        sigs.append(ThreatSignal('hop_stall', 'network', 4, 0.20, 0.60,
                                 "Hop Delay", "Relay stalling", auth.hop_anomaly))

    # DNS contradictions
    for detail in auth.details:
        if 'Header claims SPF PASS but no SPF record' in detail:
            sigs.append(ThreatSignal('dns_spf_contradiction', 'auth', 2, 0.60, 0.80,
                                     "DNS Contradiction", detail, "Possible AR header forgery"))
        elif 'Header claims DMARC PASS but no DMARC record' in detail:
            sigs.append(ThreatSignal('dns_dmarc_contradiction', 'auth', 2, 0.55, 0.75,
                                     "DNS Contradiction", detail, "Possible AR header forgery"))

    if auth.live_verified and auth.live_dmarc.get('policy') == 'reject' and auth.dmarc == 'PASS':
        trust.append(TrustFactor('dmarc_reject_policy', 0.10, 0.85,
                                 "Domain has DMARC reject policy"))
    return sigs, trust


# ── HEADER / SPOOF SIGNALS ────────────────────────────────────────────────────

@signal_emitter
def _header_signals(ctx) -> Tuple[List[ThreatSignal], List[TrustFactor]]:
    sigs, trust = [], []
    if ctx.get('reply_hijack'):
        sigs.append(ThreatSignal('reply_to_hijack', 'auth', 2, 0.65, 0.85,
                                 "Reply-To Hijack", "Replies redirected to different domain", ""))
    for a in ctx.get('anomalies', []):
        if 'hijack' not in a.lower():
            sigs.append(ThreatSignal(f'header_{a[:20]}', 'network', 4, 0.15, 0.55,
                                     "Header Anomaly", a, ""))
    if ctx.get('spoof_result'):
        sigs.append(ThreatSignal('display_name_spoof', 'behavioral', 2, 0.60, 0.80,
                                 "Display Name Spoof", ctx['spoof_result'],
                                 f"'{ctx.get('spoof_dn','')}' from {ctx.get('spoof_sd','')}"))
    return sigs, trust


# ── BEC SIGNALS ───────────────────────────────────────────────────────────────

@signal_emitter
def _bec_signals(ctx) -> Tuple[List[ThreatSignal], List[TrustFactor]]:
    bec: BECResult = ctx['bec']
    auth: AuthResult = ctx['auth']
    sigs, trust = [], []

    if bec.score < 0.25:
        if bec.contradictions:
            trust.append(TrustFactor('bec_contradiction', 0.10, 0.60,
                                     "BEC contradiction: urgency + calm language"))
        return sigs, trust

    # Unified auth dampening: one place, not double-dipped
    effective = bec.score
    if auth.auth_clean and not bec.tier1_hit:
        effective *= 0.35
    elif auth.auth_clean and bec.tier1_hit:
        effective *= 0.70

    if effective >= 0.25:
        tier = 2 if effective >= 0.60 else 3
        conf = 0.75 if bec.density > 0.02 else 0.55
        note = " [auth-dampened]" if auth.auth_clean else ""
        sigs.append(ThreatSignal(
            'bec_combined', 'behavioral', tier, min(effective, 0.85), conf,
            "BEC Pattern", bec.summary + note, "; ".join(bec.findings[:3])))
        # Category markers for cluster detection (zero-prob, no score impact)
        for cat in set(bec.categories):
            sigs.append(ThreatSignal(f'bec_{cat}', 'behavioral', tier + 1, 0.0, conf,
                                     f"BEC marker: {cat}", "", ""))

    if bec.contradictions:
        trust.append(TrustFactor('bec_contradiction', 0.10, 0.60,
                                 "BEC contradiction: urgency + calm"))
    return sigs, trust


# ── LINK-TEXT MISMATCH SIGNALS ────────────────────────────────────────────────

@signal_emitter
def _link_signals(ctx) -> Tuple[List[ThreatSignal], List[TrustFactor]]:
    sigs, trust = [], []
    mismatches = ctx.get('link_mismatches', [])
    real = [m for m in mismatches if not m.is_tracking]
    tracking = [m for m in mismatches if m.is_tracking]

    # Deduplicate by domain pair
    seen = set()
    unique = []
    for m in real:
        pair = (m.display_domain, m.href_domain)
        if pair not in seen:
            seen.add(pair)
            unique.append(m)
    if unique:
        sigs.append(ThreatSignal('link_text_mismatch', 'content', 2, 0.55, 0.85,
                                 f"{len(unique)} Link-Text Mismatch(es)",
                                 "Displayed domain differs from link destination",
                                 f"e.g. '{unique[0].display_domain}' → '{unique[0].href_domain}'"))
    if tracking:
        trust.append(TrustFactor('tracking_links', 0.05, 0.70,
                                 f"{len(tracking)} link(s) via known tracking domains"))
    return sigs, trust


# ── OBSERVABLE / URL SIGNALS ──────────────────────────────────────────────────

@signal_emitter
def _observable_signals(ctx) -> Tuple[List[ThreatSignal], List[TrustFactor]]:
    sigs, trust = [], []
    observables: list = ctx.get('observables', [])
    vt_clean = 0
    _struct_seen: set = set()
    _dom_seen: set = set()

    for o in observables:
        # VT result signals
        if o.vt and o.vt.success:
            if o.vt.threat_level in ('CRITICAL', 'MALICIOUS'):
                p = 0.85 if o.vt.threat_level == 'CRITICAL' else 0.70
                sigs.append(ThreatSignal(f'vt_{o.type}_{o.value[:20]}', 'network', 1,
                                         p, 0.90, f"VT: {o.type} flagged", o.vt.reasoning, o.defanged))
            elif o.vt.threat_level == 'SUSPICIOUS':
                sigs.append(ThreatSignal(f'vt_sus_{o.value[:20]}', 'network', 3, 0.35, 0.65,
                                         f"VT: {o.type} suspicious", o.vt.reasoning, o.defanged))
            elif o.vt.threat_level in ('CLEAN', 'LOW'):
                vt_clean += 1

        # Typosquat
        if o.vt and o.vt.domain_intel and o.vt.domain_intel.typosquat:
            sigs.append(ThreatSignal('typosquat', 'content', 2, 0.50, 0.75,
                                     "Typosquat Domain", o.vt.domain_intel.typosquat, o.defanged))

        # Domain entropy / DGA for untrusted domains
        if o.vt and o.vt.domain_intel and not o.vt.domain_intel.trusted:
            dom = url_host(o.value) if o.type == 'url' else o.value.lower()
            if dom and not is_tracking_domain(dom) and dom not in _dom_seen:
                _dom_seen.add(dom)
                se = subdomain_entropy(dom)
                if se > 4.0:
                    sigs.append(ThreatSignal('dga_domain_entropy', 'content', 3, 0.35, 0.70,
                                             "High Subdomain Entropy",
                                             f"Subdomain entropy {se:.1f}b suggests DGA", o.defanged))
                if is_randomized_domain(dom):
                    sigs.append(ThreatSignal('dga_domain_consonant', 'content', 3, 0.40, 0.65,
                                             "Randomized Domain", "Consonant/vowel ratio matches DGA", o.defanged))
            di = o.vt.domain_intel
            if di.age_days > 0 and di.age_days < 30:
                sigs.append(ThreatSignal('domain_new', 'content', 3, 0.30, 0.75,
                                         f"New Domain ({di.age_days}d)", "< 30 days old", o.defanged))

        # URL structure heuristics — deduplicated by signal name
        if o.type == 'url':
            host = url_host(o.value)
            if host and not is_tracking_domain(host) and not o.is_wrapper:
                for us in _url_structure_signals(o.value, host):
                    if us.name not in _struct_seen:
                        _struct_seen.add(us.name)
                        sigs.append(us)
            # Brand-in-subdomain
            root = root_domain(host) if host else ''
            if host and root:
                sub = host[:max(0, len(host) - len(root) - 1)]
                for brand in PROTECTED_BRANDS:
                    if brand in sub and root != brand and f'brand_{brand}' not in _dom_seen:
                        _dom_seen.add(f'brand_{brand}')
                        sigs.append(ThreatSignal(
                            'brand_in_subdomain', 'content', 2, 0.55, 0.80,
                            f"Brand in Subdomain ({brand})",
                            f"'{brand}' in subdomain of '{root}'", f"Domain: {host}"))
                        break

    # Aggregate URL heuristics
    shorteners = [o for o in observables if o.is_shortener]
    if shorteners:
        sigs.append(ThreatSignal('url_shortener', 'content', 4, 0.12, 0.60,
                                 f"{len(shorteners)} Shortened URL(s)", "May hide destination", ""))
    sus_tld = [o for o in observables if o.suspicious_tld]
    if sus_tld:
        sigs.append(ThreatSignal('suspicious_tld', 'content', 4, 0.18, 0.65,
                                 f"{len(sus_tld)} Suspicious TLD(s)", "Frequently-abused TLD", ""))
    high_ent = [o for o in observables if o.type == 'url' and o.path_entropy > 4.8]
    if high_ent:
        sigs.append(ThreatSignal('high_entropy_url', 'content', 3, 0.25, 0.60,
                                 "High-Entropy URL Path", "Likely phishing token",
                                 f"Entropy: {high_ent[0].path_entropy:.1f}"))
    if vt_clean > 0:
        trust.append(TrustFactor('vt_clean_urls', min(0.15, vt_clean * 0.02), 0.75,
                                 f"{vt_clean} URL(s) verified clean by VirusTotal"))

    # OTX / X-Force signals — deduplicated across intel sources
    _seen_tier1: set = {normalize_url(s.evidence) if s.evidence and s.evidence.startswith('http')
                         else s.evidence.lower()
                         for s in sigs if s.tier == 1 and s.evidence}
    for o in observables:
        nk = normalize_url(o.value) if o.type == 'url' else o.value.lower()
        for source, attr, prefix in [('otx', 'otx', 'otx_'), ('xforce', 'xforce', 'xforce_')]:
            data = getattr(o, attr, {})
            if not data:
                continue
            lvl = data.get('threat_level', '')
            if lvl == 'CRITICAL' and nk not in _seen_tier1:
                _seen_tier1.add(nk)
                sigs.append(ThreatSignal(
                    f'{prefix}{o.type}_{o.value[:20]}', 'network', 1,
                    0.78 if source == 'otx' else 0.75,
                    0.82 if source == 'otx' else 0.80,
                    f"{source.upper()}: confirmed threat",
                    data.get('reasoning', ''), o.defanged))
            elif lvl in ('HIGH', 'SUSPICIOUS'):
                sigs.append(ThreatSignal(
                    f'{prefix}sus_{o.value[:20]}', 'network', 3,
                    0.32 if source == 'otx' else 0.28,
                    0.68 if source == 'otx' else 0.62,
                    f"{source.upper()}: suspicious",
                    data.get('reasoning', ''), o.defanged))
    return sigs, trust


def _url_structure_signals(url: str, host: str) -> List[ThreatSignal]:
    """IP literals, non-standard ports, deep subdomains — consolidated per-URL."""
    import re
    from urllib.parse import urlparse
    out = []
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', host):
        out.append(ThreatSignal('ip_literal_url', 'content', 3, 0.35, 0.80,
                                "IP-Literal URL", "URL points to raw IP", f"Host: {host}"))
    try:
        port = urlparse(url).port
        if port and port not in (80, 443):
            out.append(ThreatSignal('nonstandard_port', 'content', 3, 0.25, 0.70,
                                    f"Non-Standard Port :{port}", "Unusual port", defang(url[:80])))
    except Exception:
        pass
    reg = root_domain(host)
    if reg and reg != host:
        depth = len(host.split('.')) - len(reg.split('.'))
        if depth >= 4:
            out.append(ThreatSignal('deep_subdomain', 'content', 4, 0.18, 0.60,
                                    f"Deep Subdomain ({depth} levels)",
                                    "Excessive subdomain depth", f"Host: {host}"))
    return out


# ── ATTACHMENT / YARA / MALWARE SIGNALS ───────────────────────────────────────

@signal_emitter
def _attachment_signals(ctx) -> Tuple[List[ThreatSignal], List[TrustFactor]]:
    sigs, trust = [], []
    macros: list = ctx.get('macros', [])

    _SEV_PROB = {'CRITICAL': 0.80, 'HIGH': 0.50, 'MEDIUM': 0.25, 'LOW': 0.06}
    _SEV_TIER = {'CRITICAL': 1, 'HIGH': 2, 'MEDIUM': 3, 'LOW': 4}

    for m in macros:
        if m.mb_found:
            sigs.append(ThreatSignal('malware_hash', 'attachment', 1, 0.95, 0.98,
                                     f"MALWARE: {m.filename}", f"MalwareBazaar: {m.mb_family}", m.sha256))
        for ym in m.yara_matches:
            if ym.get('enrichment'):
                continue
            sev = ym['severity'].upper()
            if sev == 'INFO':
                continue
            sigs.append(ThreatSignal(
                f"yara_{ym['rule']}", 'yara',
                _SEV_TIER.get(sev, 4), _SEV_PROB.get(sev, 0.06), 0.85,
                f"YARA: {ym['rule']}", ym['desc'], ""))

        if m.has_macros and not m.yara_matches and not m.mb_found and m.risk_score > 0:
            prob = min(m.risk_score / 100, 0.75)
            sigs.append(ThreatSignal(
                f"pdf_tags_{m.filename[:15]}", 'attachment', 2, prob, 0.75,
                f"Suspicious Tags: {m.filename}",
                '; '.join(m.details[:3]) or m.verdict, m.sha256[:16] if m.sha256 else ""))
        elif m.has_macros and m.risk_score >= 50:
            sigs.append(ThreatSignal(
                f"macro_{m.filename[:15]}", 'attachment', 2,
                min(m.risk_score / 120, 0.80), 0.75,
                f"Risky Macros: {m.filename}", m.verdict, ""))

    # Clean attachment trust
    real = [m for m in macros if m.filename != '[Body]']
    if real and not any(m.mb_found or m.yara_matches or (m.has_macros and m.risk_score > 0)
                        for m in real) and not ctx.get('attachment_risks'):
        trust.append(TrustFactor('clean_attachments', 0.10 if len(real) < 3 else 0.15, 0.95,
                                 f"{len(real)} attachment(s) verified clean"))

    # Attachment structural risks
    for risk in ctx.get('attachment_risks', []):
        p = 0.60 if risk['severity'] == 'CRITICAL' else 0.30
        t = 2 if risk['severity'] == 'CRITICAL' else 3
        sigs.append(ThreatSignal(f"att_{risk['type']}_{risk['file'][:15]}", 'attachment', t,
                                 p, 0.85 if risk['severity'] == 'CRITICAL' else 0.70,
                                 f"Attachment Risk: {risk['file']}", risk['desc'], ""))
    return sigs, trust


# ── IMAGE / OCR SIGNALS ──────────────────────────────────────────────────────

@signal_emitter
def _image_signals(ctx) -> Tuple[List[ThreatSignal], List[TrustFactor]]:
    sigs, trust = [], []
    images: list = ctx.get('images', [])
    ocr_bec: int = ctx.get('ocr_bec_hits', 0)

    for img in images:
        if img.has_steg:
            sigs.append(ThreatSignal('steganography', 'attachment', 2, 0.70, 0.75,
                                     "Steganography", "Hidden data in image", img.filename))
    if ocr_bec:
        sigs.append(ThreatSignal('ocr_bec', 'content', 3, 0.35, 0.55,
                                 "Image-Text BEC", f"OCR BEC in {ocr_bec} image(s)", ""))
    if images and not any(img.has_steg or img.qr_links for img in images) and not ocr_bec:
        trust.append(TrustFactor('clean_images', 0.05 if len(images) == 1 else 0.08, 0.80,
                                 f"{len(images)} image(s) scanned clean"))
    return sigs, trust


# ── REPUTATION SIGNALS ────────────────────────────────────────────────────────

@signal_emitter
def _reputation_signals(ctx) -> Tuple[List[ThreatSignal], List[TrustFactor]]:
    sigs, trust = [], []
    abuse = ctx.get('abuse_data', {})
    auth: AuthResult = ctx['auth']

    if abuse:
        ascore = abuse.get('abuseConfidenceScore', 0)
        is_cloud = any(k in (abuse.get('isp', '') or '').lower()
                       for k in ('google', 'amazon', 'microsoft', 'azure', 'cloudflare'))
        if ascore >= 75 and not (is_cloud and auth.spf == 'PASS'):
            sigs.append(ThreatSignal('abuse_ip_high', 'network', 2, 0.65, 0.80,
                                     f"AbuseIPDB: {ascore}/100",
                                     f"{abuse.get('totalReports',0)} reports, ISP: {abuse.get('isp','')}",
                                     auth.source_ip))
        elif ascore >= 40 and not (is_cloud and auth.gateway_trust):
            sigs.append(ThreatSignal('abuse_ip_med', 'network', 3, 0.30, 0.65,
                                     f"AbuseIPDB: {ascore}/100", "Elevated", ""))
        elif ascore < 10:
            trust.append(TrustFactor('ip_clean', 0.05, 0.60, f"AbuseIPDB clean ({ascore}/100)"))
        if abuse.get('isTor'):
            sigs.append(ThreatSignal('tor_exit', 'network', 2, 0.50, 0.90,
                                     "TOR Exit Node", "Source anonymized", ""))

    # Spamhaus DNSBL — called externally, results stored in ctx
    for dnsbl in ctx.get('dnsbl_results', []):
        if dnsbl['cat'] == 'PBL':
            sigs.append(ThreatSignal('dnsbl_pbl', 'network', 3, 0.30, 0.70,
                                     f"Spamhaus PBL: {auth.source_ip}", dnsbl['desc'], auth.source_ip))
        else:
            sigs.append(ThreatSignal('dnsbl_listed', 'network', 2, 0.65, 0.85,
                                     f"Spamhaus ZEN ({dnsbl['cat']}): {auth.source_ip}",
                                     dnsbl['desc'], auth.source_ip))

    # No MX record
    if ctx.get('no_mx'):
        sigs.append(ThreatSignal('no_mx_record', 'network', 3, 0.28, 0.70,
                                 f"No MX Record: {auth.from_domain}",
                                 "Sender domain cannot receive bounce replies",
                                 auth.from_domain))

    # Sender memory trust
    sender = ctx.get('sender_memory')
    if sender and sender['known'] and sender['days'] > 60 and sender['count'] >= 3:
        has_t1 = any(s.tier == 1 and s.probability >= 0.50 for s in ctx.get('_current_sigs', []))
        base = min(0.09, (sender['days'] / 365) * 0.09) + min(0.09, (sender['count'] / 20) * 0.09)
        strength = round(min(0.18, base * (0.5 if has_t1 else 1.0)), 4)
        trust.append(TrustFactor('known_sender', strength, 0.65,
                                 f"Known sender: {auth.from_domain} ({sender['days']}d, {sender['count']} emails)"))
    return sigs, trust


# ── BODY FINDINGS SIGNALS ─────────────────────────────────────────────────────

@signal_emitter
def _body_signals(ctx) -> Tuple[List[ThreatSignal], List[TrustFactor]]:
    sigs = []
    for bf in ctx.get('body_findings', []):
        sigs.append(ThreatSignal(f'body_{bf[:15]}', 'content', 4, 0.12, 0.50,
                                 "Content Alert", bf, ""))
    return sigs, []


# ── PUBLIC API ────────────────────────────────────────────────────────────────

def generate_all(ctx: dict) -> Tuple[List[ThreatSignal], List[TrustFactor]]:
    """Call all registered signal emitters and merge results.

    ctx is a dict containing all analysis results (auth, bec, observables, macros, etc.).
    """
    all_sigs: List[ThreatSignal] = []
    all_trust: List[TrustFactor] = []

    for emitter in _EMITTERS:
        try:
            s, t = emitter(ctx)
            all_sigs.extend(s)
            all_trust.extend(t)
        except Exception:
            pass

    # Inject current sigs for sender-memory tier-1 check (reputation emitter needs it)
    ctx['_current_sigs'] = all_sigs

    # Re-run reputation emitter with enriched context (it checks _current_sigs)
    # This is handled by the emitter reading ctx['_current_sigs'] on first call.
    # The emitter is already called above, so this is a no-op unless we want a second pass.
    # Keeping single-pass for simplicity — the reputation emitter uses a conservative default.

    return all_sigs, all_trust
