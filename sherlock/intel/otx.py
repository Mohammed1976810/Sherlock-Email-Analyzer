"""AlienVault OTX threat intelligence."""
from __future__ import annotations
from ..constants import HTTP_TIMEOUT

_cache: dict = {}


def check_otx(kind: str, value: str, api_key: str = "") -> dict:
    if not value:
        return {}
    ck = f"otx:{kind}:{value}"
    if ck in _cache:
        return _cache[ck]
    result = {}
    try:
        import requests, urllib.parse
        headers = {'X-OTX-API-KEY': api_key} if api_key else {}
        _ENDPOINTS = {
            'ip': f"https://otx.alienvault.com/api/v1/indicators/IPv4/{value}/general",
            'domain': f"https://otx.alienvault.com/api/v1/indicators/domain/{value}/general",
            'url': f"https://otx.alienvault.com/api/v1/indicators/url/{urllib.parse.quote(value, safe='')}/general",
            'hash': f"https://otx.alienvault.com/api/v1/indicators/file/{value}/general",
        }
        url = _ENDPOINTS.get(kind)
        if not url:
            return {}
        resp = requests.get(url, headers=headers, timeout=HTTP_TIMEOUT)
        if resp.status_code == 200:
            d = resp.json()
            pc = d.get('pulse_info', {}).get('count', 0)
            families = list({t for p in d.get('pulse_info', {}).get('pulses', []) for t in p.get('malware_families', []) if t})[:5]
            tags = list({t for p in d.get('pulse_info', {}).get('pulses', []) for t in p.get('tags', []) if t})[:8]
            _LEVELS = [(10, 'CRITICAL'), (3, 'HIGH'), (1, 'SUSPICIOUS'), (0, 'CLEAN')]
            level = next(l for thresh, l in _LEVELS if pc >= thresh)
            result = {
                'pulse_count': pc, 'threat_score': min(100, pc * 8),
                'malware_families': families, 'tags': tags,
                'threat_level': level, 'reasoning': f"OTX: {pc} pulse(s)",
            }
        elif resp.status_code == 404:
            result = {'pulse_count': 0, 'threat_level': 'CLEAN', 'reasoning': 'OTX: Not found'}
    except Exception:
        pass
    _cache[ck] = result
    return result
