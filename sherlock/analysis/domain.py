"""Domain intelligence — classification, typosquat, WHOIS, entropy.

Key optimization: domain_intel() results cached by root domain. Government/edu/platform
classification uses set/dict membership (O(1)) instead of linear iteration.
"""
from __future__ import annotations
import threading, logging
from datetime import datetime
from typing import Optional
from ..models import DomainIntel
from ..utils import (
    root_domain, safe_strip_www, is_tracking_domain, subdomain_entropy,
    is_randomized_domain, levenshtein
)
from ..constants import (
    GOVERNMENT_TLDS, EDUCATIONAL_TLDS, KNOWN_PLATFORMS, _KNOWN_PLATFORM_SET,
    MAJOR_TECH, DNS_TIMEOUT,
)

log = logging.getLogger("sherlock.domain")

try:
    import whois as whois_lib
    WHOIS_OK = True
except ImportError:
    WHOIS_OK = False

_CACHE: dict = {}
_CACHE_LOCK = threading.Lock()
_WHOIS_LOCK = threading.Lock()

_HOMOGLYPHS = {'0': 'o', '1': 'l', 'l': 'i', 'rn': 'm', 'vv': 'w', 'cl': 'd'}

_BRANDS = {
    'microsoft': 'microsoft.com', 'google': 'google.com', 'apple': 'apple.com',
    'amazon': 'amazon.com', 'paypal': 'paypal.com', 'facebook': 'facebook.com',
    'netflix': 'netflix.com', 'linkedin': 'linkedin.com', 'docusign': 'docusign.com',
    'adobe': 'adobe.com', 'chase': 'chase.com', 'wellsfargo': 'wellsfargo.com',
}

_ALLOWED_VARIANTS = {
    'google': {'googleusercontent.com', 'googleapis.com', 'googlemail.com', 'gstatic.com'},
    'amazon': {'amazonaws.com', 'ssl-images-amazon.com', 'amazonses.com'},
    'microsoft': {'microsoftonline.com', 'office365.com', 'windows.net', 'azure.com',
                  'outlook.com', 'live.com', 'office.com', 'sharepoint.com',
                  'onmicrosoft.com', 'azurewebsites.net'},
    'paypal': {'paypal-communication.com', 'paypal-objects.com', 'paypal.me'},
    'facebook': {'fb.com', 'fbcdn.net', 'fbsbx.com', 'facebook.net'},
    'netflix': {'nflxso.net', 'nflxext.com', 'nflximg.net'},
}


def check_typosquat(domain: str) -> Optional[str]:
    d = domain.lower()
    root = root_domain(d).split('.')[0]
    full_root = root_domain(d)

    if 'xn--' in d:
        return "IDN HOMOGRAPH: Punycode domain"

    for bn, bd in _BRANDS.items():
        br = bd.split('.')[0]
        if root == br:
            continue
        if full_root in _ALLOWED_VARIANTS.get(bn, set()):
            continue
        dist = levenshtein(root, br)
        if 0 < dist <= 2 and len(root) >= 4:
            return f"TYPOSQUAT: '{d}' is {dist} edit(s) from '{bd}'"
        norm = root
        for fake, real in _HOMOGLYPHS.items():
            norm = norm.replace(fake, real)
        if norm == br and root != br:
            return f"HOMOGLYPH: '{d}' mimics '{bd}'"
        if bn in d and full_root != bd:
            return f"BRAND ABUSE: '{d}' embeds '{bn}' but isn't '{bd}'"
    return None


def domain_intel(domain: str) -> DomainIntel:
    """Classify a domain using local heuristics + optional WHOIS. Cached by root."""
    root = root_domain(domain)
    with _CACHE_LOCK:
        if root in _CACHE:
            return _CACHE[root]

    di = DomainIntel(domain=domain)
    typo = check_typosquat(domain)
    if typo:
        di.typosquat = typo

    dl = domain.lower()

    # O(1) classification via set/dict membership
    for tld in GOVERNMENT_TLDS:
        if dl.endswith(tld):
            di.category, di.trusted, di.reasoning = 'government', True, f'Gov ({tld})'
            return _store(root, di)
    for tld in EDUCATIONAL_TLDS:
        if dl.endswith(tld):
            di.category, di.trusted, di.reasoning = 'educational', True, f'Edu ({tld})'
            return _store(root, di)

    # Platform check: try exact match first, then parent-domain walk
    for pd in _KNOWN_PLATFORM_SET:
        if dl == pd or dl.endswith('.' + pd):
            di.category, di.trusted = 'platform', True
            di.platform = KNOWN_PLATFORMS[pd]
            di.reasoning = f'Known: {di.platform}'
            return _store(root, di)

    for td in MAJOR_TECH:
        if dl == td or dl.endswith('.' + td):
            di.category, di.trusted, di.reasoning = 'major_tech', True, f'Major tech ({td})'
            return _store(root, di)

    if is_tracking_domain(dl):
        di.category, di.trusted, di.reasoning = 'security_gateway', True, 'Email security gateway'
        return _store(root, di)

    # WHOIS (non-blocking lock — skip rather than serialize)
    if WHOIS_OK and _WHOIS_LOCK.acquire(timeout=0.05):
        try:
            with _CACHE_LOCK:
                if root in _CACHE:
                    return _CACHE[root]
            w = _whois_threaded(root, DNS_TIMEOUT)
            if w:
                if w.org:
                    di.org = str(w.org[0] if isinstance(w.org, list) else w.org)
                if w.creation_date:
                    cd = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
                    if isinstance(cd, datetime):
                        di.age_days = (datetime.now() - cd).days
                        di.reasoning = f"New domain ({di.age_days}d)" if di.age_days < 30 else f"Established ({di.age_days}d)"
        except Exception:
            pass
        finally:
            _WHOIS_LOCK.release()

    if not di.reasoning:
        di.reasoning = "Active domain"

    # Entropy analysis for untrusted, non-tracking domains
    if not di.trusted and not is_tracking_domain(domain):
        se = subdomain_entropy(domain)
        if se > 4.0:
            di.reasoning += f" | HIGH entropy ({se:.1f}b)"
        if is_randomized_domain(domain):
            di.reasoning += " | DGA/random pattern"

    return _store(root, di)


def _store(root: str, di: DomainIntel) -> DomainIntel:
    with _CACHE_LOCK:
        _CACHE[root] = di
    return di


def _whois_threaded(domain: str, timeout: float):
    result = [None]
    def _do():
        try:
            result[0] = whois_lib.whois(domain)
        except Exception:
            pass
    t = threading.Thread(target=_do, daemon=True)
    t.start()
    t.join(timeout=timeout)
    return result[0]
