"""Header anomaly detection and display-name spoof checking."""
from __future__ import annotations
import re, email.header, email.utils
from datetime import datetime, timezone
from typing import Tuple, List, Optional
from ..constants import (
    PAT_DOMAIN, PAT_TZ, LEGIT_MAILERS, DISPLAY_NAME_BRANDS,
    DISPLAY_NAME_TITLES, FREEMAIL_DOMAINS, SUSPICIOUS_TLDS,
)
from ..utils import root_domain


def analyze_headers(msg) -> Tuple[List[str], bool]:
    anomalies = []
    reply_hijack = False

    mailer = str(msg.get('X-Mailer', '') or msg.get('User-Agent', '')).lower()
    if mailer and not any(l in mailer for l in LEGIT_MAILERS):
        if re.search(r'[a-z]{8,}v\d+', mailer) or mailer in ('test', 'spam', 'bulk'):
            anomalies.append(f"Unusual X-Mailer: '{mailer[:50]}'")

    from_addr = str(msg.get('From', ''))
    reply_to = str(msg.get('Reply-To', ''))
    if reply_to:
        fd = PAT_DOMAIN.search(from_addr)
        rd = PAT_DOMAIN.search(reply_to)
        if fd and rd and root_domain(fd.group(1).lower()) != root_domain(rd.group(1).lower()):
            reply_hijack = True
            anomalies.append(f"REPLY-TO HIJACK: From={fd.group(1)} vs Reply-To={rd.group(1)}")

    tzs = set()
    for h in msg.get_all('Received', []) or []:
        m = PAT_TZ.search(str(h))
        if m:
            tzs.add(m.group(0))
    if len(tzs) > 4:
        anomalies.append(f"Timezone spread: {len(tzs)} zones")

    if not msg.get('Message-ID'):
        anomalies.append("Missing Message-ID")

    date_str = str(msg.get('Date', ''))
    if date_str:
        try:
            md = email.utils.parsedate_to_datetime(date_str)
            now = datetime.now(timezone.utc) if md.tzinfo else datetime.now()
            diff = (md - now).days
            if diff > 3:
                anomalies.append(f"Future date: {diff}d ahead")
            elif diff < -30:
                anomalies.append(f"Stale date: {abs(diff)}d in the past (possible replay)")
        except Exception:
            pass

    return anomalies, reply_hijack


def check_display_spoof(msg, org_domain: str = "") -> Tuple[Optional[str], str, str]:
    """Returns (spoof_reason, display_name, sender_domain) or (None, dn, sd)."""
    from_h = str(msg.get('From', '')).strip()
    try:
        from_h = str(email.header.make_header(email.header.decode_header(from_h)))
    except Exception:
        pass

    m = re.match(r'^"?([^"<@\n]{2,60}?)"?\s*<([^>]+)>', from_h)
    if not m:
        return None, "", ""
    dn = m.group(1).strip()
    addr = m.group(2).strip().lower()
    dm = PAT_DOMAIN.search(addr)
    if not dm:
        return None, dn, ""
    sd = dm.group(1).lower()
    if org_domain and sd.endswith(org_domain):
        return None, dn, sd

    dnl = dn.lower()

    # Header injection
    if '@' in dnl and '.' in dnl:
        return "HEADER INJECTION: Display name contains email", dn, sd

    # Brand impersonation
    for brand in DISPLAY_NAME_BRANDS:
        if brand in dnl and brand.replace(' ', '') not in sd:
            return f"BRAND SPOOF: Claims '{dn}' from '{sd}'", dn, sd

    # Title spoof (only on freemail / suspicious TLD)
    sd_root = root_domain(sd)
    is_freemail = sd_root in FREEMAIL_DOMAINS
    is_sus = any(sd.endswith(t) for t in SUSPICIOUS_TLDS)
    if is_freemail or is_sus:
        for title in DISPLAY_NAME_TITLES:
            if title in dnl:
                reason = "freemail" if is_freemail else "suspicious TLD"
                return f"TITLE SPOOF: Claims '{dn}' from {reason} domain '{sd}'", dn, sd

    return None, dn, sd
