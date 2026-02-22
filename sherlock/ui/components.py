"""Shared HTML component builders — pure functions, no Streamlit calls."""
from __future__ import annotations
import re
from ..utils import esc
from .styles import DC, SHADOW, tc


def card(icon: str, title: str, body: str, detail: str, color: str) -> str:
    body_html = re.sub(r'\*\*(.+?)\*\*', r'<b>\1</b>', esc(body))
    return (
        f"<div style='background:linear-gradient(135deg,{DC['card']},{DC['elev']});"
        f"border:1px solid {color}44;border-left:4px solid {color};"
        f"border-radius:10px;padding:14px 16px;margin:6px 0;box-shadow:{SHADOW}'>"
        f"<div style='font-weight:700;color:{color};margin-bottom:6px;font-size:.95em'>"
        f"{icon} {esc(title)}</div>"
        f"<div style='color:{DC['text1']};font-size:.88em;margin-bottom:6px;line-height:1.5'>"
        f"{body_html}</div>"
        f"<div style='color:{DC['text2']};font-size:.76em;border-top:1px solid {DC['border']};"
        f"padding-top:5px;margin-top:4px'>{esc(detail[:160])}</div></div>"
    )


def md_to_html(text: str) -> str:
    """Convert **bold** markdown to <b> tags, with HTML escaping."""
    return re.sub(r'\*\*(.+?)\*\*', r'<b>\1</b>', esc(text))


def severity_color(eff: float) -> tuple:
    if eff >= 0.4:
        return DC['critical'], "CRITICAL"
    if eff >= 0.2:
        return DC['high'], "HIGH"
    if eff >= 0.08:
        return DC['medium'], "MEDIUM"
    return DC['low'], "LOW"


def signal_card_html(title: str, detail: str, evidence: str,
                     eff: float, category: str) -> str:
    sc, sev = severity_color(eff)
    tab_map = {
        'auth': '🔐 Authentication', 'attachment': '📎 Attachments',
        'yara': '🔴 YARA', 'network': '🌐 URLs & Domains',
        'content': '🌐 URLs & Domains', 'behavioral': '🧠 Narrative',
    }
    target = tab_map.get(category, '📊 All Findings')
    t2 = DC['text2']
    bdr = DC['border']
    acc = DC['accent']
    ev = f"<div style='color:{t2};font-size:.85em;margin-top:6px;font-style:italic'>{esc(evidence)}</div>" if evidence else ''
    return (
        f"<div style='background:rgba(0,0,0,0.25);border-radius:8px;padding:14px 18px;"
        f"margin:8px 0;border-left:4px solid {sc}'>"
        f"<div style='display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:6px'>"
        f"<span style='font-weight:700;color:{sc};font-size:1em'>{esc(title)}</span>"
        f"<span style='background:{sc};color:#fff;padding:2px 10px;border-radius:10px;"
        f"font-size:.75em;font-weight:700'>{sev} ({eff:.0%})</span></div>"
        f"<div style='color:#cbd5e1;font-size:.9em;margin-top:6px'>"
        f"<span style='color:{bdr}'>Why: </span>{esc(detail)}</div>"
        f"{ev}"
        f"<div style='margin-top:10px;padding-top:8px;border-top:1px solid {bdr}44;text-align:right'>"
        f"<span style='color:{acc};background:{acc}15;padding:4px 10px;"
        f"border-radius:6px;font-size:.78em;font-weight:600'>👉 {target} tab</span></div></div>"
    )
