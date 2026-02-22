"""Observable extraction — URLs, domains, IPs from email body and headers.

Key change: single BS4 parse shared between visible text extraction and URL extraction.
"""
from __future__ import annotations
import re
from typing import List, Tuple, Set
from ..models import Observable, LinkMismatch
from ..utils import (
    normalize_url, url_host, url_path_entropy, safe_strip_www,
    is_tracking_domain, is_redirect_wrapper, extract_inner_url, defang,
    root_domain
)
from ..constants import (
    PAT_URL, PAT_HREF, PAT_EMAIL, PAT_IPV4, PRIVATE_IP_PATTERNS,
    MAX_HTML_SIZE, MAX_OBS, URL_SHORTENERS, SUSPICIOUS_TLDS,
)

try:
    from bs4 import BeautifulSoup, Comment
    BS4_OK = True
except ImportError:
    BS4_OK = False


def extract_visible_text(html_body: str) -> str:
    if not html_body:
        return ""
    if len(html_body) > MAX_HTML_SIZE:
        html_body = html_body[:MAX_HTML_SIZE]
    if not BS4_OK:
        return re.sub(r'<[^>]+>', ' ', html_body)
    soup = BeautifulSoup(html_body, 'html.parser')
    for tag in soup.find_all(['script', 'style', 'head', 'noscript']):
        tag.decompose()
    for tag in list(soup.find_all(True)):
        style = tag.get('style', '') or ''
        if 'display:none' in style.replace(' ', '') or 'visibility:hidden' in style.replace(' ', ''):
            tag.decompose()
    for comment in soup.find_all(string=lambda t: isinstance(t, Comment)):
        comment.extract()
    return soup.get_text(separator=' ', strip=True)


def extract_observables(msg, html_body: str, text_body: str) -> Tuple[List[Observable], List[LinkMismatch]]:
    obs: List[Observable] = []
    mismatches: List[LinkMismatch] = []
    seen: Set[str] = set()

    def _add(typ, val, src, **kw):
        norm = normalize_url(val) if typ == 'url' else val.lower()
        key = f"{typ}:{norm}"
        if key in seen:
            return
        seen.add(key)
        o = Observable(type=typ, value=val, defanged=defang(val), source=src, **kw)
        if typ == 'url':
            try:
                netloc = url_host(val)
                o.is_shortener = netloc in URL_SHORTENERS
                o.suspicious_tld = any(netloc.endswith(t) for t in SUSPICIOUS_TLDS)
                is_gw = is_tracking_domain(netloc)
                wrapper = is_redirect_wrapper(val)
                if is_gw or wrapper:
                    o.path_entropy = 0.0
                    o.is_wrapper = True
                else:
                    o.path_entropy = url_path_entropy(val)
                if wrapper:
                    inner = extract_inner_url(val)
                    if inner and inner != val:
                        _add('url', inner, 'gateway_inner')
            except Exception:
                o.path_entropy = url_path_entropy(val)
        elif typ == 'domain':
            o.suspicious_tld = any(val.lower().endswith(t) for t in SUSPICIOUS_TLDS)
        obs.append(o)

    # HTML href extraction + link-text mismatch (single BS4 parse)
    if BS4_OK and html_body:
        soup = BeautifulSoup(html_body[:MAX_HTML_SIZE], 'html.parser')
        for a in soup.find_all('a', href=True):
            href = a['href'].strip()
            if not href.startswith(('http://', 'https://')):
                continue
            _add('url', href, 'html_href')
            display = a.get_text(strip=True)
            if display:
                dm = re.search(r'(?:https?://)?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', display)
                if dm:
                    dd = safe_strip_www(dm.group(1).lower())
                    if dd.endswith(('.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico')):
                        continue
                    hd = url_host(href)
                    hr, dr = root_domain(hd), root_domain(dd)
                    if hr != dr:
                        is_track = is_tracking_domain(hd)
                        mismatches.append(LinkMismatch(
                            href=href, display=display[:80],
                            href_domain=hd, display_domain=dd, is_tracking=is_track))
    elif html_body:
        for m in PAT_HREF.finditer(html_body[:MAX_HTML_SIZE]):
            href = m.group(1).strip()
            if href.startswith(('http://', 'https://')):
                _add('url', href, 'html_href')

    body = (html_body or '') + (text_body or '')
    for url in PAT_URL.findall(body)[:MAX_OBS]:
        _add('url', url, 'body')

    for ea in PAT_EMAIL.findall(str(msg))[:MAX_OBS]:
        _add('domain', ea.split('@')[1].lower(), 'header')

    from ..utils import is_private_ip
    for h in msg.get_all('Received', []) or []:
        for ip in PAT_IPV4.findall(str(h)):
            if not is_private_ip(ip):
                _add('ip', ip, 'received')

    return obs, mismatches
