"""IP/domain reputation — AbuseIPDB + Spamhaus DNSBL + MX validation."""
from __future__ import annotations
from typing import Tuple, Dict
from ..constants import HTTP_TIMEOUT, DNS_TIMEOUT, PRIVATE_IP_PATTERNS
from ..utils import is_private_ip

try:
    import dns.resolver; DNS_OK = True
except ImportError: DNS_OK = False

_SPAMHAUS_CATS = {
    '127.0.0.2': ('SBL', 'Spamhaus Block List — verified spam source'),
    '127.0.0.3': ('SBL', 'Spamhaus Block List — verified spam source'),
    '127.0.0.4': ('XBL', 'Exploits Block List — infected host'),
    '127.0.0.5': ('XBL', 'Exploits Block List — infected host'),
    '127.0.0.9': ('SBL', 'Spamhaus Block List — policy block'),
    '127.0.0.10': ('PBL', 'Policy Block List — dynamic/residential IP'),
    '127.0.0.11': ('PBL', 'Policy Block List — dynamic/residential IP'),
}


def check_abuseipdb(ip: str, api_key: str) -> Dict:
    if not ip or not api_key:
        return {}
    try:
        import requests
        resp = requests.get('https://api.abuseipdb.com/api/v2/check',
                            headers={'Key': api_key, 'Accept': 'application/json'},
                            params={'ipAddress': ip, 'maxAgeInDays': '90', 'verbose': ''},
                            timeout=HTTP_TIMEOUT)
        if resp.status_code == 200:
            return resp.json().get('data', {})
    except Exception:
        pass
    return {}


def check_spamhaus(ip: str) -> Tuple[bool, str, str]:
    if not DNS_OK or not ip:
        return False, '', ''
    parts = ip.split('.')
    if len(parts) != 4 or not all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        return False, '', ''
    if is_private_ip(ip):
        return False, '', ''
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = DNS_TIMEOUT
        resolver.lifetime = DNS_TIMEOUT
        query = f"{'.'.join(reversed(parts))}.zen.spamhaus.org"
        answers = resolver.resolve(query, 'A')
        for ans in answers:
            cat, desc = _SPAMHAUS_CATS.get(str(ans), ('LISTED', f'Listed ({ans})'))
            return True, cat, desc
        return True, 'LISTED', 'Listed in Spamhaus ZEN'
    except Exception:
        return False, '', ''


def check_mx(domain: str) -> Tuple[bool, str]:
    if not DNS_OK or not domain:
        return True, ''
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = DNS_TIMEOUT
        resolver.lifetime = DNS_TIMEOUT
        answers = resolver.resolve(domain, 'MX')
        mx_hosts = [str(r.exchange).rstrip('.') for r in answers]
        return True, ', '.join(mx_hosts[:3])
    except dns.resolver.NXDOMAIN:
        return False, 'No MX records — domain cannot receive email'
    except dns.resolver.NoAnswer:
        return False, 'No MX records found'
    except Exception:
        return True, ''
