"""Email authentication analysis — SPF, DKIM, DMARC, gateway, routing."""
from __future__ import annotations
import re, email.utils
from datetime import datetime, timezone
from ..models import AuthResult
from ..constants import PAT_DOMAIN, PAT_IPV4, PAT_TZ, PRIVATE_IP_PATTERNS, MARKETING_RP_DOMAINS
from ..utils import root_domain, is_private_ip

try:
    import dns.resolver
    DNS_OK = True
except ImportError:
    DNS_OK = False


def get_source_ip(msg) -> str:
    for h in reversed(msg.get_all('Received', []) or []):
        for ip in PAT_IPV4.findall(str(h)):
            if not is_private_ip(ip):
                return ip
    return ""


def _dns_record(domain: str, rtype: str, prefix: str = '') -> dict:
    """Generic DNS TXT lookup for SPF/DMARC."""
    if not DNS_OK:
        return {'status': 'UNKNOWN'}
    try:
        from ..constants import DNS_TIMEOUT
        resolver = dns.resolver.Resolver()
        resolver.timeout = DNS_TIMEOUT
        resolver.lifetime = DNS_TIMEOUT
        qname = f"{prefix}{domain}" if prefix else domain
        for rd in resolver.resolve(qname, 'TXT'):
            t = rd.to_text().strip('"')
            if rtype == 'spf' and 'v=spf1' in t:
                return {'status': 'FOUND', 'record': t}
            if rtype == 'dmarc' and 'v=DMARC1' in t:
                pm = re.search(r'p=(\w+)', t)
                return {'status': 'FOUND', 'policy': pm.group(1) if pm else 'none', 'record': t}
        return {'status': 'MISSING'}
    except Exception:
        return {'status': 'MISSING'}


def _ar_check(protocol: str, result: str, headers: list) -> bool:
    pat = re.compile(rf'\b{protocol}\s*=\s*{result}\b', re.I)
    return any(pat.search(str(h)) for h in headers)


def analyze_auth(msg) -> AuthResult:
    r = AuthResult()
    r.source_ip = get_source_ip(msg)
    r.hop_count, r.hop_delays, r.hop_anomaly = _analyze_hops(msg)
    if r.hop_anomaly:
        r.details.append(r.hop_anomaly)

    ar = msg.get_all('Authentication-Results', []) or []
    spf_h = msg.get_all('Received-SPF', []) or []

    # Vendor SPF pass (with injection guard)
    _pat = re.compile(r'(?<!=)\bspf\s*=\s*pass\b', re.I)
    vendor_pass = any(_pat.search(str(msg.get(h, '')))
                      for h in ['X-FEAS-SPF', 'X-Forefront-Antispam-Report'])

    # SPF
    sh_pass = any(re.search(r'\bpass\b', str(h), re.I) for h in spf_h)
    sh_fail = any(re.search(r'\bfail\b', str(h), re.I) and not re.search(r'\bsoftfail\b', str(h), re.I) for h in spf_h)
    sh_soft = any(re.search(r'\bsoftfail\b', str(h), re.I) for h in spf_h)

    _SPF_RULES = [
        (lambda: vendor_pass or _ar_check('spf', 'pass', ar) or sh_pass, 'PASS', "SPF: PASS"),
        (lambda: _ar_check('spf', 'fail', ar) or sh_fail, 'FAIL', "SPF: FAIL"),
        (lambda: _ar_check('spf', 'softfail', ar) or sh_soft, 'SOFTFAIL', "SPF: SOFTFAIL"),
    ]
    for check, val, finding in _SPF_RULES:
        if check():
            r.spf = val
            r.findings.append(finding)
            break
    else:
        r.findings.append("SPF: NONE")

    # DKIM (dict mapping)
    for result_val in ('pass', 'fail'):
        if _ar_check('dkim', result_val, ar):
            r.dkim = result_val.upper()
            r.findings.append(f"DKIM: {r.dkim}")
            break
    else:
        r.findings.append("DKIM: NONE")

    # DMARC
    for result_val in ('pass', 'fail'):
        if _ar_check('dmarc', result_val, ar):
            r.dmarc = result_val.upper()
            r.findings.append(f"DMARC: {r.dmarc}")
            break
    else:
        r.findings.append("DMARC: NONE")

    # Gateway detection
    _GW = [
        ('X-Mimecast-Spam-Score', 'Mimecast', lambda v: int(v) <= 1),
        ('X-IronPort-AV', 'Cisco IronPort', lambda v: True),
        ('X-Barracuda-Spam-Score', 'Barracuda', lambda v: float(v) <= 1),
    ]
    for hdr, name, check in _GW:
        val = msg.get(hdr, '')
        if val:
            try:
                if check(val):
                    r.gateway_trust = True
                    r.gateway_name = name
                    r.details.append(f"Gateway: {name}")
            except Exception:
                pass
    if msg.get('X-Proofpoint-Spam-Details'):
        r.gateway_trust = True
        r.gateway_name = r.gateway_name or "Proofpoint"

    # Require auth corroboration for gateway trust
    if r.gateway_trust and r.spf != 'PASS' and r.dkim != 'PASS':
        r.gateway_trust = False
        r.details.append(f"Gateway '{r.gateway_name}' discarded — no SPF/DKIM PASS to corroborate")
        r.gateway_name = ""

    # Domains + shadow spoof
    r.from_full = str(msg.get('From', ''))
    r.rp_full = str(msg.get('Return-Path', ''))
    fm = PAT_DOMAIN.search(r.from_full)
    rm = PAT_DOMAIN.search(r.rp_full)
    if fm:
        r.from_domain = fm.group(1).lower()
        if DNS_OK:
            r.live_verified = True
            r.live_dmarc = _dns_record(r.from_domain, 'dmarc', '_dmarc.')
            r.live_spf = _dns_record(r.from_domain, 'spf')
            if r.spf == 'PASS' and r.live_spf.get('status') == 'MISSING':
                r.details.append("WARNING: Header claims SPF PASS but no SPF record found in DNS")
            if r.dmarc == 'PASS' and r.live_dmarc.get('status') == 'MISSING':
                r.details.append("WARNING: Header claims DMARC PASS but no DMARC record in DNS")
    if fm and rm:
        r.rp_domain = rm.group(1).lower()
        rp_root = root_domain(r.rp_domain)
        if r.from_domain != r.rp_domain and rp_root not in MARKETING_RP_DOMAINS:
            r.shadow_spoof = True
            r.findings.append(f"SHADOW SPOOF: {r.from_domain} vs {r.rp_domain}")

    return r


def _analyze_hops(msg):
    headers = msg.get_all('Received', []) or []
    count = len(headers)
    timestamps = []
    for h in reversed(headers):
        parts = str(h).rsplit(';', 1)
        if len(parts) == 2:
            try:
                timestamps.append(email.utils.parsedate_to_datetime(parts[1].strip()))
            except Exception:
                pass

    delays = []
    for i in range(1, len(timestamps)):
        try:
            delays.append((timestamps[i] - timestamps[i - 1]).total_seconds())
        except Exception:
            pass

    anomaly = ""
    stalls = [(i + 1, d) for i, d in enumerate(delays) if d > 900]
    if stalls:
        worst = max(stalls, key=lambda x: x[1])
        anomaly = f"Hop {worst[0]} stalled {worst[1]/60:.0f}min"
    elif count == 0:
        anomaly = "No Received headers — locally crafted?"
    elif count == 1:
        anomaly = "Single hop — unusual for internet email"
    elif count > 15:
        anomaly = f"Excessive hops ({count})"
    return count, delays, anomaly
