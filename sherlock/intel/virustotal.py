"""VirusTotal client — rate-limited, cached, with cloud-IP FP guard."""
from __future__ import annotations
import base64, threading, time
from ..models import VTResult
from ..analysis.domain import domain_intel
from ..utils import url_host
from ..constants import HTTP_TIMEOUT, VT_WEIGHTS

_VT_LOCK = threading.Lock()
_last_call = [0.0]
_call_count = [0]
_window_start = [time.time()]


def _rate_wait():
    """Rate limiter: 4 req/min, 15s spacing (VT free tier)."""
    while True:
        sleep_needed = 0.0
        with _VT_LOCK:
            now = time.time()
            if now - _window_start[0] > 60:
                _call_count[0] = 0
                _window_start[0] = now
            if _call_count[0] >= 4:
                sleep_needed = max(0.0, 60 - (now - _window_start[0]) + 1)
            elif _call_count[0] > 0:
                elapsed = now - _last_call[0]
                if elapsed < 15:
                    sleep_needed = 15 - elapsed
            if sleep_needed <= 0:
                _last_call[0] = time.time()
                _call_count[0] += 1
                return
        time.sleep(min(sleep_needed, 2.0))


_cache: dict = {}
_cache_lock = threading.Lock()


def _cached(key):
    with _cache_lock:
        return _cache.get(key)


def _store(key, val):
    with _cache_lock:
        if len(_cache) > 800:
            for old in list(_cache)[:200]:
                del _cache[old]
        _cache[key] = val


def _consensus(stats, detailed=None, is404=False, dom="", is_cloud=False, di=None) -> VTResult:
    r = VTResult()
    if dom:
        r.domain_intel = di if di is not None else domain_intel(dom)
    if is404:
        r.success, r.is_new = True, True
        r.threat_level = "CLEAN" if (r.domain_intel and r.domain_intel.trusted) else "UNKNOWN"
        r.reasoning = "Not in VT" if r.threat_level == "UNKNOWN" else f"Trusted: {r.domain_intel.reasoning}"
        return r
    r.total = sum(stats.values()) if stats else 0
    r.malicious = stats.get('malicious', 0)
    r.success = True
    if detailed:
        r.engines = [e for e, d in detailed.items()
                     if isinstance(d, dict) and d.get('category') == 'malicious']
    w = sum(VT_WEIGHTS.get(e, 1) for e in r.engines)
    r.weighted = w
    t1 = sum(1 for e in r.engines if VT_WEIGHTS.get(e, 0) >= 3)

    _RULES = [
        (r.malicious == 0, "CLEAN", f"Clean ({stats.get('harmless', 0)} safe)"),
        (t1 >= 2, "CRITICAL", f"{t1} major vendors flagged"),
        (w >= 5, "CRITICAL", f"Consensus: {r.malicious} engines"),
        (r.malicious >= 3 and not (is_cloud and t1 == 0 and w < 4),
         "MALICIOUS", f"{r.malicious} engines"),
        (r.malicious >= 3 and is_cloud and t1 == 0 and w < 4,
         "SUSPICIOUS", f"{r.malicious} minor engines (cloud IP)"),
        (r.malicious >= 2, "SUSPICIOUS", f"{r.malicious} engines"),
        (r.malicious == 1, "UNKNOWN", "Single engine flag"),
    ]
    for cond, level, reason in _RULES:
        if cond:
            r.threat_level, r.reasoning = level, reason
            break
    return r


def check_vt(kind: str, value: str, vt_key: str = "") -> VTResult:
    ck = f"{kind}:{value}"
    cached = _cached(ck)
    if cached:
        return cached

    dom = ""
    if kind == 'url':
        try: dom = url_host(value)
        except Exception: pass
    elif kind == 'domain':
        dom = value

    di = domain_intel(dom) if dom else None

    if not vt_key:
        r = VTResult(success=True, error="No API key")
        r.domain_intel = di
        r.threat_level = "CLEAN" if (di and di.trusted) else ("SUSPICIOUS" if (di and di.typosquat) else "UNKNOWN")
        r.reasoning = f"No VT API — {di.reasoning if di else 'no local intel'}"
        _store(ck, r)
        return r

    if di and di.trusted:
        r = VTResult(success=True, error="Trusted — VT skipped")
        r.domain_intel = di
        r.threat_level, r.reasoning = "CLEAN", f"Local: {di.reasoning}"
        _store(ck, r)
        return r

    try:
        import requests
        _rate_wait()
        h = {"x-apikey": vt_key}
        if kind == 'url':
            uid = base64.urlsafe_b64encode(value.encode()).decode().strip("=")
            resp = requests.get(f"https://www.virustotal.com/api/v3/urls/{uid}", headers=h, timeout=HTTP_TIMEOUT)
        elif kind == 'domain':
            resp = requests.get(f"https://www.virustotal.com/api/v3/domains/{value}", headers=h, timeout=HTTP_TIMEOUT)
        else:
            resp = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{value}", headers=h, timeout=HTTP_TIMEOUT)

        if resp.status_code == 200:
            a = resp.json().get('data', {}).get('attributes', {})
            _cloud_kw = ('microsoft', 'google', 'amazon', 'cloudflare', 'akamai')
            _as = (a.get('as_owner') or '').lower()
            r = _consensus(a.get('last_analysis_stats', {}), a.get('last_analysis_results', {}),
                           False, dom, any(k in _as for k in _cloud_kw), di)
        elif resp.status_code == 404:
            r = _consensus({}, {}, True, dom, False, di)
        else:
            r = VTResult(error=f"HTTP {resp.status_code}")
            r.domain_intel = di
        _store(ck, r)
        return r
    except Exception as e:
        r = VTResult(error=str(e)[:80])
        r.domain_intel = di
        return r
