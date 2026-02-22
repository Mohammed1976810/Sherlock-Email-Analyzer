"""IBM X-Force Exchange threat intelligence."""
from __future__ import annotations
from ..constants import HTTP_TIMEOUT

_cache: dict = {}


def check_xforce(kind: str, value: str, api_key: str = "", api_secret: str = "") -> dict:
    if not value or not api_key or not api_secret:
        return {}
    ck = f"xf:{kind}:{value}"
    if ck in _cache:
        return _cache[ck]
    result = {}
    try:
        import requests, urllib.parse
        auth = (api_key, api_secret)
        headers = {'Accept': 'application/json'}
        if kind == 'ip':
            resp = requests.get(f"https://api.xforce.ibmcloud.com/ipr/{value}",
                                auth=auth, headers=headers, timeout=HTTP_TIMEOUT)
        elif kind in ('domain', 'url'):
            encoded = urllib.parse.quote(value, safe='')
            resp = requests.get(f"https://api.xforce.ibmcloud.com/url/{encoded}",
                                auth=auth, headers=headers, timeout=HTTP_TIMEOUT)
        elif kind == 'hash':
            resp = requests.get(f"https://api.xforce.ibmcloud.com/malware/{value}",
                                auth=auth, headers=headers, timeout=HTTP_TIMEOUT)
        else:
            return {}

        if resp.status_code == 200:
            d = resp.json()
            if kind == 'ip':
                score = float(d.get('score', 0))
                cats = list(d.get('cats', {}).keys())[:5]
            elif kind in ('domain', 'url'):
                inner = d.get('url', d.get('result', d))
                score = float(inner.get('score', 0))
                cats = list(inner.get('cats', {}).keys())[:5]
            else:
                score = 10.0 if d.get('malware', {}).get('family') else 0.0
                cats = [d.get('malware', {}).get('family', '')] if d.get('malware', {}).get('family') else []

            _LEVELS = [(7, 'CRITICAL'), (5, 'HIGH'), (2, 'SUSPICIOUS'), (0, 'CLEAN')]
            level = next(l for thresh, l in _LEVELS if score >= thresh)
            result = {
                'risk_score': score, 'categories': cats,
                'threat_level': level,
                'reasoning': f"X-Force score {score:.1f}/10" + (f" ({', '.join(cats)})" if cats else ""),
            }
        elif resp.status_code == 404:
            result = {'risk_score': 0, 'threat_level': 'CLEAN', 'reasoning': 'X-Force: Not found'}
    except Exception:
        pass
    _cache[ck] = result
    return result
