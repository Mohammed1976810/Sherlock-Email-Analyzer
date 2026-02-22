"""Shared utilities — small, pure, no side effects."""
from __future__ import annotations
import html, math, hashlib, unicodedata, re
from collections import Counter
from urllib.parse import urlparse, unquote
from typing import Optional
from .constants import (
    COMPOUND_TLDS, _COMPOUND_TLD_PARTS, TRACKING_ALLOWLIST,
    PRIVATE_IP_PATTERNS, SUSPICIOUS_TLDS, URL_SHORTENERS,
)

# ── Unicode confusable table ──────────────────────────────────────────────────
_CONFUSABLES = str.maketrans({
    '\u0430': 'a', '\u0435': 'e', '\u043e': 'o', '\u0440': 'p', '\u0441': 'c',
    '\u0443': 'y', '\u0445': 'x', '\u0456': 'i', '\u0458': 'j', '\u0455': 's',
    '\u0391': 'A', '\u0392': 'B', '\u0395': 'E', '\u0397': 'H', '\u0399': 'I',
    '\u039a': 'K', '\u039c': 'M', '\u039d': 'N', '\u039f': 'O', '\u03a1': 'P',
    '\u03a4': 'T', '\u03a7': 'X', '\u03a5': 'Y', '\u0396': 'Z',
})

# ── Root domain cache ─────────────────────────────────────────────────────────
_root_cache: dict = {}


def esc(t) -> str:
    """HTML-escape any value. Returns '' only for None."""
    return "" if t is None else html.escape(str(t))


def root_domain(d: str) -> str:
    """Extract registrable domain using O(1) set lookup for compound TLDs.

    Previous: linear scan over 150+ compound TLD strings.
    Now: split into parts, check last 2/3 against the frozenset.
    """
    if not d:
        return d
    cached = _root_cache.get(d)
    if cached is not None:
        return cached
    dl = d.lower()
    p = dl.split('.')
    if len(p) >= 3:
        maybe2 = '.'.join(p[-2:])  # e.g. "co.uk"
        if maybe2 in COMPOUND_TLDS:
            result = '.'.join(p[-(2 + 1):])  # name.co.uk
            _root_cache[d] = result
            return result
    if len(p) >= 4:
        maybe3 = '.'.join(p[-3:])
        # Some compound TLDs are 3-part; but our set is 2-part. This handles edge cases.
    result = '.'.join(p[-2:]) if len(p) >= 2 else dl
    _root_cache[d] = result
    return result


def safe_strip_www(domain: str) -> str:
    d = domain.lower()
    return d[4:] if d.startswith('www.') else d


def url_host(url: str) -> str:
    """Extract hostname from URL — no port, lowercase, no www."""
    try:
        h = urlparse(url).hostname
        return safe_strip_www(h) if h else ''
    except Exception:
        return ''


def normalize_url(url: str) -> str:
    """Normalize for deduplication: lowercase host, strip default port and trailing slash."""
    try:
        p = urlparse(url)
        host = p.hostname or p.netloc
        _DEFAULT = {('https', 443), ('http', 80)}
        if p.port and (p.scheme, p.port) in _DEFAULT:
            netloc = host.lower()
        else:
            netloc = p.netloc.lower()
        path = p.path.rstrip('/')
        norm = f"{p.scheme}://{netloc}{path}"
        if p.query:
            norm += f"?{p.query}"
        return norm
    except Exception:
        return url.rstrip('/')


def is_private_ip(ip: str) -> bool:
    return any(r.match(ip) for r in PRIVATE_IP_PATTERNS)


def is_tracking_domain(domain: str) -> bool:
    """O(depth) parent-domain walk with O(1) set lookups at each step."""
    d = safe_strip_www(domain.lower())
    if d in TRACKING_ALLOWLIST:
        return True
    r = root_domain(d)
    if r in TRACKING_ALLOWLIST:
        return True
    parts = d.split('.')
    for i in range(1, len(parts) - 1):
        if '.'.join(parts[i:]) in TRACKING_ALLOWLIST:
            return True
    return False


def defang(v: str) -> str:
    if not isinstance(v, str):
        return str(v)
    return esc(
        v.replace('http://', 'hxxp://')
         .replace('https://', 'hxxps://')
         .replace('.', '\u200b[.]\u200b')
    )


def shannon_entropy(data) -> float:
    if not data:
        return 0.0
    if isinstance(data, str):
        data = data.encode('utf-8', 'ignore')
    if not data:
        return 0.0
    c = Counter(data)
    n = len(data)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def url_path_entropy(url: str) -> float:
    try:
        parsed = urlparse(url)
        path = parsed.path + (parsed.query or '')
        if len(path) < 5:
            return 0.0
        c = Counter(path)
        n = len(path)
        return -sum((v / n) * math.log2(v / n) for v in c.values())
    except Exception:
        return 0.0


def normalize_text(text: str) -> str:
    if not text:
        return ""
    text = unicodedata.normalize('NFKC', text)
    text = text.translate(_CONFUSABLES)
    text = re.sub(r'(?<=\w)[.\-_\s]{1,2}(?=\w)', '', text)
    return text


def subdomain_entropy(domain: str) -> float:
    """Shannon entropy of leftmost label. Guards against structured hostnames."""
    if not domain:
        return 0.0
    parts = domain.split('.')
    if len(parts) <= 2:
        return 0.0
    label = parts[0]
    if len(label) <= 5:
        return 0.0
    if '-' in label:
        segments = label.split('-')
        if all(s.isalpha() or s.isdigit() or (len(s) <= 4 and s.isalnum())
               for s in segments if s) and len(segments) >= 2:
            return 0.0
    if all(c in '0123456789abcdef-' for c in label.lower()) and len(label) <= 16:
        return 0.0
    return shannon_entropy(label)


def is_randomized_domain(domain: str) -> bool:
    """Detect DGA-style names via consonant clustering and vowel ratio."""
    root = root_domain(domain).split('.')[0]
    if not root or len(root) < 8 or '-' in root:
        return False
    vowels = set('aeiou')
    alpha = [c for c in root.lower() if c.isalpha()]
    if len(alpha) < 7:
        return False
    vratio = sum(1 for c in alpha if c in vowels) / len(alpha)
    if vratio < 0.15:
        return True
    max_cons = cur = 0
    for c in alpha:
        if c not in vowels:
            cur += 1
            max_cons = max(max_cons, cur)
        else:
            cur = 0
    return max_cons >= 6


def levenshtein(a: str, b: str) -> int:
    if len(a) < len(b):
        return levenshtein(b, a)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (ca != cb)))
        prev = curr
    return prev[-1]


def is_redirect_wrapper(url: str) -> bool:
    try:
        parsed = urlparse(url)
        raw = parsed.path + ('?' + parsed.query if parsed.query else '')
        if not raw:
            return False
        once = unquote(raw)
        if 'http://' in once or 'https://' in once:
            return True
        twice = unquote(once)
        return 'http://' in twice or 'https://' in twice
    except Exception:
        return False


def extract_inner_url(url: str) -> Optional[str]:
    """Extract the real destination URL from a redirect wrapper."""
    try:
        from urllib.parse import parse_qs
        parsed = urlparse(url)
        if not parsed.query:
            return None
        params = parse_qs(parsed.query)
        for param in ('url', 'redirect', 'redirecturl', 'destination',
                       'dest', 'goto', 'target', 'link', 'return', 'u', 'q'):
            if param in params:
                candidate = unquote(params[param][0])
                if candidate.startswith(('http://', 'https://')):
                    return candidate
        from .constants import PAT_URL
        for decoded in (unquote(parsed.query), unquote(unquote(parsed.query))):
            found = PAT_URL.search(decoded)
            if found:
                return found.group(0)
        return None
    except Exception:
        return None


def filter_display_signals(signals) -> list:
    """Filter zero-probability BEC markers. Single source for this logic."""
    return [s for s in signals
            if not (s.probability == 0.0 and s.name.startswith('bec_')
                    and s.name != 'bec_combined')]
