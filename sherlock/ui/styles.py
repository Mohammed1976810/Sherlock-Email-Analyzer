"""Theme constants — single source of truth for all UI colors."""

DC = {
    'critical': '#ef4444', 'high': '#f97316', 'medium': '#eab308',
    'low': '#64748b', 'safe': '#22c55e',
    'unknown': '#94a3b8', 'bg': '#0f172a', 'card': '#1e293b',
    'elev': '#2d3748', 'border': '#334155', 'accent': '#38bdf8',
    'purple': '#8b5cf6',
    'text1': '#e2e8f0', 'text2': '#94a3b8',
    'ok': '#10b981', 'warn': '#f59e0b', 'err': '#ef4444',
}
SHADOW = '0 4px 6px -1px rgba(0,0,0,0.3)'

_TC_MAP = {
    'CRITICAL': DC['critical'], 'MALICIOUS': DC['critical'],
    'LIKELY MALICIOUS': DC['high'], 'HIGH': DC['high'],
    'SUSPICIOUS': DC['medium'], 'MEDIUM': DC['medium'],
    'LOW': DC['low'], 'REVIEW': DC['accent'],
    'CLEAN': DC['safe'], 'SAFE': DC['safe'],
}
_TI_MAP = {
    'CRITICAL': '🚨', 'MALICIOUS': '🚨', 'LIKELY MALICIOUS': '🚨',
    'HIGH': '⚠️', 'SUSPICIOUS': '⚠️', 'MEDIUM': '⚠️',
    'LOW': '📋', 'REVIEW': '📋', 'CLEAN': '✅', 'SAFE': '✅',
}


def tc(level: str) -> str:
    return _TC_MAP.get((level or '').upper(), DC['unknown'])


def ti(level: str) -> str:
    return _TI_MAP.get((level or '').upper(), '❓')


PAGE_CSS = f"""<style>
.main{{background:linear-gradient(135deg,{DC['bg']} 0%,#1a1f2e 100%)}}
.stProgress > div > div > div > div{{background-image:linear-gradient(90deg,{DC['accent']},{DC['purple']},{DC['high']});border-radius:10px}}
.stTabs [data-baseweb="tab-list"]{{gap:6px;background:{DC['card']};padding:8px;border-radius:10px}}
.stTabs [data-baseweb="tab"]{{border-radius:8px;padding:10px 18px}}
.stTabs [aria-selected="true"]{{background:linear-gradient(135deg,{DC['accent']},{DC['purple']});box-shadow:0 0 20px rgba(59,130,246,0.3)}}
[data-testid="stMetricValue"]{{font-size:2em;font-weight:700;background:linear-gradient(135deg,{DC['accent']},{DC['purple']});-webkit-background-clip:text;-webkit-text-fill-color:transparent}}
</style>"""
