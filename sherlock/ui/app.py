"""Sherlock Streamlit UI — pure display layer.

Every tab reads from a pre-computed DisplayReport dict (D).
Zero math, zero string parsing, zero list comprehensions in rendering.
All computation happens in display.prepare_display() before this code runs.
"""
from __future__ import annotations
import hashlib, time
import streamlit as st
import pandas as pd
from ..utils import esc, defang
from ..display import prepare_display
from ..reports import generate_pdf
from .styles import DC, SHADOW, PAGE_CSS, tc, ti
from .components import card, md_to_html


def main():
    st.set_page_config(page_title="Sherlock", layout="wide", page_icon="🔍")
    st.markdown(PAGE_CSS, unsafe_allow_html=True)
    st.title("🔍 SHERLOCK — FORENSIC EMAIL ANALYZER")
    st.caption("Signal Engine | Cluster Intelligence | Risk Narrative | Behavioral Patterns")

    # ── Session state init ────────────────────────────────────────────────
    for key, default in [('report', None), ('display', None), ('fhash', None),
                         ('elapsed', None)]:
        if key not in st.session_state:
            st.session_state[key] = default

    # ── Sidebar ───────────────────────────────────────────────────────────
    with st.sidebar:
        st.markdown("### 📧 Upload Email")
        up = st.file_uploader("Select .eml file", type=['eml'])
        fb = None
        if up:
            fb = up.getvalue()
            fh = hashlib.md5(fb).hexdigest()
            sz = len(fb) / (1024 * 1024)
            if sz > 50:
                st.error("❌ File too large (>50MB)")
                st.stop()
            st.success(f"✅ Loaded ({sz:.2f} MB)")
            if st.session_state.fhash != fh:
                st.session_state.fhash = fh
                st.session_state.report = None
                st.session_state.display = None

    if not up:
        st.info("👈 Upload an .eml file to begin analysis")
        return

    # ── Analysis (runs once per file) ─────────────────────────────────────
    try:
        if st.session_state.report is None:
            pb = st.progress(0)
            sc = st.empty()

            def _status(m, i):
                sc.markdown(
                    f"<div style='background:linear-gradient(90deg,{DC['accent']}22,transparent);"
                    f"border-left:4px solid {DC['accent']};padding:12px 16px;border-radius:6px;"
                    f"margin:8px 0;box-shadow:{SHADOW}'>"
                    f"<span style='font-size:1.1em;margin-right:8px'>{i}</span>"
                    f"<span style='color:{DC['text1']};font-weight:500'>{esc(m)}</span></div>",
                    unsafe_allow_html=True)

            from ..pipeline import analyze_email
            t0 = time.time()

            # Pull API keys from Streamlit secrets (safe defaults)
            _sec = lambda k: st.secrets.get(k, "") if hasattr(st, 'secrets') else ""
            R = analyze_email(
                fb, _status, pb.progress,
                vt_key=_sec("vt_api_key"), abuse_key=_sec("abuseipdb_key"),
                otx_key=_sec("otx_api_key"), xforce_key=_sec("xforce_api_key"),
                xforce_secret=_sec("xforce_api_secret"),
            )

            # Pre-compute ALL display data immediately after analysis
            D = prepare_display(R)

            st.session_state.report = R
            st.session_state.display = D
            st.session_state.elapsed = round(time.time() - t0, 1)

            sc.empty()
            pb.empty()
            st.rerun()  # Clean render pass — no analysis, only display

        # ── FROM HERE ON: pure display from pre-computed D ────────────────
        if st.session_state.elapsed:
            st.success(f"✅ Analysis complete in {st.session_state.elapsed:.1f}s")

        R = st.session_state.report
        D = st.session_state.display
        if D is None:
            st.warning("Display data not ready. Please re-upload.")
            return

        v = D['verdict']

        # ── Verdict card ──────────────────────────────────────────────────
        st.markdown(
            f"<div style='background:linear-gradient(135deg,{DC['card']},{DC['elev']});"
            f"padding:24px;border-radius:12px;margin:16px 0;border-left:6px solid {v['color']};"
            f"box-shadow:0 10px 15px -3px rgba(0,0,0,0.4)'>"
            f"<div style='display:flex;align-items:center;gap:14px;flex-wrap:wrap;margin-bottom:10px'>"
            f"<h2 style='margin:0;color:{DC['text1']}'>{v['icon']} Verdict: {esc(v['verdict'])}</h2>"
            f"<span style='background:{v['action_color']};color:#fff;padding:6px 14px;"
            f"border-radius:20px;font-weight:700;font-size:.9em'>{v['action_label']}</span></div>"
            + (f"<div style='margin-bottom:10px'><span style='background:{v['color']}22;"
               f"border:1px solid {v['color']}55;border-radius:8px;padding:4px 12px;"
               f"font-size:.82em;color:{v['color']};font-weight:600'>"
               f"⚡ Primary Attack: {esc(v['dominant_vector'])}</span></div>"
               if v['dominant_vector'] and not v['is_clean'] else "")
            + f"<div style='display:flex;flex-wrap:wrap;gap:18px;margin-top:4px'>"
            f"<span style='color:{DC['text2']}'><b>Risk Score</b>&nbsp;"
            f"<span style='color:{v['color']};font-weight:700;font-size:1.1em'>{v['score']}</span>/100</span>"
            f"<span style='color:{DC['text2']}'><b>Threat Level</b>&nbsp;"
            f"<span style='color:{v['color']};font-weight:600'>{esc(v['threat_level'])}</span></span>"
            f"<span style='color:{DC['text2']}'><b>{v['cert_header']}</b>&nbsp;"
            f"<span style='color:{v['ac_color']};font-weight:700'>{v['ac_label']}</span>"
            f"&nbsp;<span style='font-size:.82em'>({v['ac_value']}% — {v['ac_tip']})</span></span>"
            f"</div></div>", unsafe_allow_html=True)

        # ── Tabs ──────────────────────────────────────────────────────────
        tabs = st.tabs(["📋 Report", "🔐 Auth", "🌐 URLs", "📎 Attachments",
                        "🔴 YARA", "🖼️ Images", "📊 Findings", "💾 Export", "🔌 SOC"])

        with tabs[0]:
            _render_report(D)
        with tabs[1]:
            _render_auth(D)
        with tabs[2]:
            _render_urls(D)
        with tabs[3]:
            _render_attachments(D)
        with tabs[4]:
            _render_yara(D)
        with tabs[5]:
            _render_images(D)
        with tabs[6]:
            _render_findings(D)
        with tabs[7]:
            _render_export(D)
        with tabs[8]:
            _render_soc(D)

    except Exception as e:
        st.error(f"❌ Error: {e}")
        import traceback
        with st.expander("🐛 Debug"):
            st.code(traceback.format_exc())


# ═══════════════════════════════════════════════════════════════════════════════
# TAB RENDERERS — each reads ONLY from pre-computed D, zero computation
# ═══════════════════════════════════════════════════════════════════════════════

def _render_report(D: dict):
    rpt = D['report']

    # Narrative (pre-rendered HTML)
    st.markdown(rpt['narrative_html'], unsafe_allow_html=True)

    # Signal cards (pre-built HTML inside narrative)
    if rpt['signal_cards_html']:
        st.markdown(
            f"<div style='margin-top:16px;border-top:1px solid {DC['border']};padding-top:14px'>"
            f"<div style='font-size:1.05em;font-weight:700;color:{DC['text1']};margin-bottom:12px'>"
            f"🎯 DRIVING SIGNALS</div>{rpt['signal_cards_html']}</div>",
            unsafe_allow_html=True)

    # Reasoning cards
    st.markdown(
        f"<div style='background:linear-gradient(135deg,{DC['card']},{DC['elev']});"
        f"border:2px solid {DC['purple']};border-left:6px solid {DC['purple']};"
        f"border-radius:12px;padding:16px 20px;margin:12px 0'>"
        f"<div style='font-size:1.2em;font-weight:700;color:{DC['purple']}'>🧠 REASONING</div></div>",
        unsafe_allow_html=True)
    for i in range(0, len(rpt['reasoning_cards']), 2):
        cols = st.columns(2)
        for j, col in enumerate(cols):
            idx = i + j
            if idx < len(rpt['reasoning_cards']):
                with col:
                    st.markdown(rpt['reasoning_cards'][idx], unsafe_allow_html=True)

    # Trust factors
    if rpt['trust_factors'] or rpt['cluster_corrs']:
        st.markdown(
            f"<div style='background:linear-gradient(135deg,{DC['card']},{DC['elev']});"
            f"border:2px solid {DC['ok']};border-left:6px solid {DC['ok']};"
            f"border-radius:12px;padding:16px 20px;margin:16px 0'>"
            f"<div style='font-size:1.2em;font-weight:700;color:{DC['ok']}'>✅ MITIGATING FACTORS</div></div>",
            unsafe_allow_html=True)
        for tf in rpt['trust_factors']:
            st.markdown(
                f"<div style='background:{DC['card']};border-left:5px solid {DC['ok']};"
                f"border-radius:8px;padding:12px 16px;margin:6px 0'>"
                f"<span style='color:{DC['text1']};font-size:.92em'>{esc(tf.description)}"
                f" <span style='color:{DC['text2']};font-size:.82em'>"
                f"(dampening: {tf.strength:.0%})</span></span></div>",
                unsafe_allow_html=True)

    # Recommendation
    st.markdown(
        f"<div style='background:{rpt['rec_color']}15;border-left:4px solid {rpt['rec_color']};"
        f"border-radius:8px;padding:14px 18px;margin:16px 0'>"
        f"<div style='font-weight:700;color:{rpt['rec_color']};margin-bottom:4px'>📋 Recommendation</div>"
        f"<div style='color:{DC['text1']};font-size:.95em'>{rpt['rec_html']}</div></div>",
        unsafe_allow_html=True)

    # Score breakdown (expandable)
    sb = rpt['score_breakdown']
    with st.expander("🔍 Explain My Score", expanded=False):
        for i, step in enumerate(sb['steps']):
            is_last = (i == len(sb['steps']) - 1)
            st.markdown(
                f"<div style='display:flex;align-items:flex-start;gap:12px;margin:8px 0'>"
                f"<div style='width:28px;height:28px;border-radius:50%;background:{step['color']};"
                f"display:flex;align-items:center;justify-content:center;"
                f"font-weight:700;font-size:.78em;color:#fff;flex-shrink:0'>{i+1}</div>"
                f"<div style='flex:1'>"
                f"<div style='display:flex;justify-content:space-between;align-items:baseline'>"
                f"<span style='color:{DC['text1']};font-weight:600;font-size:.90em'>{esc(step['label'])}</span>"
                f"<span style='color:{step['color']};font-weight:700;font-size:.92em'>{esc(step['value'])}</span></div>"
                + (f"<div style='color:{DC['text2']};font-size:.78em;margin-top:2px'>{esc(step['tip'])}</div>"
                   if step['tip'] else "")
                + f"</div></div>", unsafe_allow_html=True)

        # Signal contributions
        if sb['signal_contributions']:
            st.markdown(f"<div style='font-weight:700;color:{DC['text1']};font-size:.95em;"
                        f"margin:12px 0 8px'>🎯 Score drivers</div>", unsafe_allow_html=True)
            _TIER_COLORS = {1: DC['critical'], 2: DC['high'], 3: DC['warn'], 4: DC['text2']}
            for sc_item in sb['signal_contributions']:
                if sc_item.get('pts_added', 0) < 0.1:
                    continue
                t_color = _TIER_COLORS.get(sc_item.get('tier', 4), DC['text2'])
                st.markdown(
                    f"<div style='background:{DC['elev']};border-radius:8px;padding:11px 14px;"
                    f"margin:5px 0;border-left:4px solid {t_color}'>"
                    f"<div style='display:flex;justify-content:space-between;align-items:center'>"
                    f"<span style='color:{DC['text1']};font-weight:600;font-size:.89em'>"
                    f"{esc(sc_item.get('title', sc_item.get('name', '')))}</span>"
                    f"<span style='color:{t_color};font-weight:700;font-size:.88em'>"
                    f"+{sc_item['pts_added']:.1f} pts</span></div></div>",
                    unsafe_allow_html=True)

    # Metadata
    with st.expander("📋 Email Metadata & Hashes"):
        m = rpt['metadata']
        c1, c2 = st.columns(2)
        with c1:
            st.markdown(f"**From:** `{m['from']}`")
            st.markdown(f"**Subject:** `{m['subject']}`")
            st.markdown(f"**Date:** `{m['date']}`")
        with c2:
            st.markdown(f"**MD5:** `{m['md5']}`")
            st.markdown(f"**SHA256:** `{m['sha256']}`")


def _render_auth(D: dict):
    a = D['auth']
    st.subheader("🔐 Email Authentication")
    c1, c2, c3, c4 = st.columns(4)
    for col, lbl, val in [(c1, "SPF", a['spf']), (c2, "DKIM", a['dkim']),
                          (c3, "DMARC", a['dmarc']), (c4, "Hops", a['hop_count'])]:
        delta = "Valid" if val == "PASS" else ("Issue" if val in ("FAIL", "SOFTFAIL") else "")
        dcol = "normal" if val == "PASS" else ("inverse" if val in ("FAIL", "SOFTFAIL") else "off")
        col.metric(lbl, val, delta=delta, delta_color=dcol)

    # Protocol detail cards
    pcols = st.columns(3)
    for col, p in zip(pcols, a['protocols']):
        with col:
            st.markdown(
                f"<div style='background:{p['color']}12;border:1px solid {p['color']}44;"
                f"border-radius:8px;padding:10px 14px'>"
                f"<div style='font-weight:700;color:{DC['text2']};font-size:.78em'>{p['proto']}</div>"
                f"<div style='font-weight:700;color:{p['color']};font-size:1.1em;margin:4px 0'>"
                f"{p['icon']} {p['val']}</div>"
                f"<div style='color:{DC['text2']};font-size:.78em'>{esc(p['explain'])}</div></div>",
                unsafe_allow_html=True)

    if a['spoof']:
        st.error(f"🎭 {a['spoof']}")
    for d in a['extra_details']:
        if any(k in d.upper() for k in ("FAIL", "SPOOF", "WARNING")):
            st.error(f"⚠️ {d}")
        elif any(k in d.upper() for k in ("PASS", "TRUSTED", "GATEWAY")):
            st.success(f"✅ {d}")
        else:
            st.info(f"ℹ️ {d}")
    for anomaly in a['anomalies']:
        st.warning(f"⚠️ {anomaly}")


def _render_urls(D: dict):
    u = D['urls']
    st.subheader("🌐 URL, Domain & IP Analysis")

    if u['real_mismatches']:
        st.error(f"🚨 **{len(u['real_mismatches'])} unique link-text mismatch(es)** "
                 f"({u['total_real_mm']} total)")
        for m in u['real_mismatches']:
            st.markdown(f"- **Display:** `{esc(m.display_domain)}` → **Links to:** `{esc(m.href_domain)}`")
    if u['tracking_mismatches']:
        with st.expander(f"🛡️ {len(u['tracking_mismatches'])} gateway rewrite(s) — normal"):
            for m in u['tracking_mismatches']:
                st.caption(f"🛡️ `{esc(m.display_domain)}` → `{esc(m.href_domain)}`")

    s1, s2, s3, s4 = st.columns(4)
    s1.metric("🔍 Scanned", u['total_scanned'])
    s2.metric("🚨 Threats", len(u['threats']))
    s3.metric("❓ Unknown", len(u['unknowns']))
    s4.metric("✅ Clean", len(u['clean']) + len(u['gateways']))

    def _show_obs(group, expanded=False):
        for c in group:
            o = c['obs']
            with st.expander(f"{c['icon']} {o.type.upper()}: {o.defanged[:60]}", expanded=expanded):
                st.markdown(
                    f"<div style='display:flex;flex-wrap:wrap;gap:6px;margin-bottom:10px'>"
                    f"<span style='background:{c['color']};color:#fff;padding:2px 9px;"
                    f"border-radius:5px;font-size:.77em;font-weight:700'>{c['level']}</span>"
                    f"<code style='color:{DC['accent']};font-size:.82em;word-break:break-all'>"
                    f"{esc(o.defanged)}</code></div>", unsafe_allow_html=True)
                if o.vt and o.vt.success:
                    st.caption(f"VT: {o.vt.threat_level} — {o.vt.reasoning}")
                if o.otx:
                    st.caption(f"OTX: {o.otx.get('reasoning', 'N/A')}")
                if o.xforce:
                    st.caption(f"X-Force: {o.xforce.get('reasoning', 'N/A')}")

    if u['threats']:
        st.markdown(f"**🚨 THREATS ({len(u['threats'])})**")
        _show_obs(u['threats'], expanded=True)
    if u['unknowns']:
        st.markdown(f"**❓ UNKNOWN ({len(u['unknowns'])})**")
        _show_obs(u['unknowns'])
    if u['gateways']:
        with st.expander(f"🛡️ {len(u['gateways'])} gateway(s)"):
            _show_obs(u['gateways'])
    if u['clean']:
        with st.expander(f"✅ {len(u['clean'])} clean"):
            _show_obs(u['clean'])


def _render_attachments(D: dict):
    att = D['attachments']
    st.subheader("📎 Attachment Analysis")
    for risk in att['risks']:
        sev = risk.get('severity', 'MEDIUM')
        fn = {'CRITICAL': st.error, 'HIGH': st.warning}.get(sev, st.info)
        fn(f"[{sev}] {risk['desc']}")

    for c in att['cards']:
        st.markdown(
            f"<div style='border-left:4px solid {c['color']};background:{c['color']}22;"
            f"padding:14px;margin:10px 0;border-radius:8px'>"
            f"<h4 style='margin:0 0 6px 0'>{c['icon']} {esc(c['filename'])}</h4>"
            f"<p style='margin:0;font-size:.9em'><b>Type:</b> {esc(c['file_type'])} | "
            f"<b>Risk:</b> {c['risk_score']}/100 | "
            f"<b>Verdict:</b> <span style='color:{c['color']};font-weight:700'>"
            f"{esc(c['verdict'])}</span></p>"
            + (f"<p style='margin:4px 0;color:{DC['text2']};font-size:.8em'>SHA256: {esc(c['sha256'])}</p>"
               if c['sha256'] else "")
            + (f"<p style='margin:4px 0;color:{DC['critical']};font-weight:700'>⚠️ MALWARE: {esc(c['mb_family'])}</p>"
               if c['mb_found'] else "")
            + "</div>", unsafe_allow_html=True)
        if c['embedded_uris']:
            with st.expander(f"🔗 {len(c['embedded_uris'])} embedded URL(s)"):
                for u in c['embedded_uris']:
                    st.code(defang(u))
        if c['details']:
            with st.expander("📋 Details"):
                for d in c['details']:
                    st.text(d)

    if not att['cards'] and not att['risks']:
        st.success("✅ No attachments to analyze")


def _render_yara(D: dict):
    y = D['yara']
    st.subheader("🔴 YARA Engine")
    if y['total'] > 0:
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Total Hits", y['total'])
        c2.metric("🔴 CRITICAL", y['sev_counts'].get('CRITICAL', 0))
        c3.metric("🟠 HIGH", y['sev_counts'].get('HIGH', 0))
        c4.metric("🟡 MEDIUM", y['sev_counts'].get('MEDIUM', 0))

        for fn, ys in y['by_file'].items():
            threat_ys = [yy for yy in ys if not yy.get('enrichment')]
            with st.expander(f"{'📎' if fn != '[Body]' else '📧'} {fn} — {len(threat_ys)} hit(s)", expanded=True):
                for yy in ys:
                    yc = tc(yy['severity'])
                    strings_html = ""
                    if yy.get('strings'):
                        matched = " | ".join(esc(s) for s in yy['strings'])
                        strings_html = (f"<div style='background:#0d1117;border-radius:4px;"
                                        f"padding:6px 10px;margin-top:6px;font-family:monospace;"
                                        f"font-size:.82em;color:#7ee787'>Matched: {matched}</div>")
                    st.markdown(
                        f"<div style='border-left:5px solid {yc};background:{yc}12;"
                        f"padding:14px 16px;margin:8px 0;border-radius:8px'>"
                        f"<span style='color:{yc};font-weight:700'>🔴 {esc(yy['rule'])}</span>"
                        f" <span style='background:{yc};color:#fff;padding:2px 10px;"
                        f"border-radius:12px;font-size:.78em;font-weight:700'>{esc(yy['severity'])}</span>"
                        f"<div style='color:{DC['text1']};margin-top:4px'>{esc(yy['desc'])}"
                        f"{'<span style=\"color:#6b7280;font-size:.8em\"> — informational</span>' if yy.get('enrichment') else ''}"
                        f"</div>{strings_html}</div>", unsafe_allow_html=True)
    else:
        st.success("✅ No YARA matches")


def _render_images(D: dict):
    imgs = D['images']
    st.subheader("🖼️ Image Forensics")
    if not imgs['cards']:
        st.success("✅ No images found")
        return
    for c in imgs['cards']:
        st.markdown(
            f"<div style='border-left:4px solid {c['color']};background:{c['color']}12;"
            f"padding:14px 16px;margin:10px 0;border-radius:8px'>"
            f"<div style='display:flex;justify-content:space-between;flex-wrap:wrap;gap:8px'>"
            f"<b style='color:{DC['text1']}'>📷 {esc(c['filename'])}</b>"
            f"<span style='background:{c['color']};color:#fff;padding:4px 14px;"
            f"border-radius:12px;font-size:.82em;font-weight:700'>{c['verdict']}</span></div>"
            f"<div style='color:{DC['text2']};font-size:.85em;margin-top:6px'>"
            f"Format: {esc(c['fmt'])} | Size: {c['size'][0]}x{c['size'][1]} | {esc(c['detail'])}</div></div>",
            unsafe_allow_html=True)
        col_img, col_info = st.columns([1, 2])
        with col_img:
            if c['data']:
                try:
                    st.image(c['data'], caption=c['filename'], use_container_width=True)
                except Exception:
                    st.caption("(Preview unavailable)")
        with col_info:
            for f in c['findings']:
                st.info(f"ℹ️ {f}")
            if c['ocr_text']:
                with st.expander("🔍 OCR Text"):
                    st.text(c['ocr_text'][:500])
            for ql in c['qr_links']:
                st.warning(f"📱 QR: `{defang(ql[:80])}`")


def _render_findings(D: dict):
    f = D['findings']
    st.subheader("📊 Complete Signal Table")
    if f['signals_df']:
        st.dataframe(pd.DataFrame(f['signals_df']), use_container_width=True, hide_index=True)
    else:
        st.success("✅ No findings")
    if f['trust_df']:
        st.subheader("🛡️ Trust Factors")
        st.dataframe(pd.DataFrame(f['trust_df']), use_container_width=True, hide_index=True)


def _render_export(D: dict):
    exp = D['export']
    st.subheader("💾 Export")
    c1, c2, c3 = st.columns(3)
    with c1:
        st.download_button("📥 TXT Report", exp['text_report'], "sherlock_report.txt", "text/plain")
    with c2:
        pdf = generate_pdf(exp['text_report'])
        if pdf:
            st.download_button("📥 PDF Report", pdf, "sherlock_report.pdf", "application/pdf")
        else:
            st.warning("Install reportlab for PDF")
    with c3:
        st.download_button("📥 JSON Data", exp['soar_json'], "sherlock_data.json", "application/json")

    st.divider()
    st.markdown("**📋 Analyst Report** (editable)")
    st.text_area("Analyst Report", value=exp['analyst_report'], height=400,
                 key="analyst_report", label_visibility="collapsed")
    st.download_button("📥 Download Analyst Report", exp['analyst_report'],
                       "sherlock_analyst_report.txt", "text/plain")


def _render_soc(D: dict):
    soc = D['soc']
    st.subheader("🔌 SOC / SOAR Integration")

    # MITRE ATT&CK
    st.markdown(f"**🛡️ MITRE ATT&CK Mappings**")
    _TACTIC_COLORS = {
        'initial-access': DC['critical'], 'execution': DC['high'],
        'defense-evasion': DC['warn'], 'credential-access': '#e879f9',
        'lateral-movement': '#f472b6', 'impact': DC['critical'],
        'command-and-control': DC['high'], 'resource-development': DC['text2'],
    }
    for t in soc['mitre']:
        tc_col = _TACTIC_COLORS.get(t['tactic'], DC['accent'])
        st.markdown(
            f"<div style='background:{DC['card']};border-left:4px solid {tc_col};"
            f"border-radius:8px;padding:10px 14px;margin:6px 0;"
            f"display:flex;align-items:center;gap:12px;flex-wrap:wrap'>"
            f"<code style='color:{tc_col};font-weight:700'>{t['id']}</code>"
            f"<span style='color:{DC['text1']};font-weight:600'>{esc(t['name'])}</span>"
            f"<span style='background:{tc_col}22;color:{tc_col};border:1px solid {tc_col}44;"
            f"padding:2px 10px;border-radius:10px;font-size:.75em'>"
            f"{t['tactic'].replace('-', ' ').upper()}</span></div>",
            unsafe_allow_html=True)
    if not soc['mitre']:
        st.success("✅ No MITRE techniques matched")

    st.divider()

    # IOCs
    st.markdown("**🧩 IOC Export**")
    iocs = soc['iocs']
    ic1, ic2, ic3 = st.columns(3)
    ic1.metric("IPs", len(iocs['ips']))
    ic2.metric("Domains", len(iocs['domains']))
    ic3.metric("URLs", len(iocs['urls']))

    ioc_tabs = st.tabs(["🌐 Domains", "🔗 URLs", "💥 IPs", "#️ Hashes"])
    _IOC_KEYS = ['domains', 'urls', 'ips']
    for ioc_tab, key in zip(ioc_tabs[:3], _IOC_KEYS):
        with ioc_tab:
            content = '\n'.join(iocs[key]) if iocs[key] else f"No {key} found"
            st.text_area(key, value=content, height=140, key=f"ioc_{key}", label_visibility="collapsed")
    with ioc_tabs[3]:
        h = iocs.get('hashes', {})
        st.text_area("hashes", value='\n'.join(f"{k}: {v}" for k, v in h.items()),
                     height=100, key="ioc_hashes", label_visibility="collapsed")

    st.divider()

    # SOAR JSON
    st.markdown("**🤖 SOAR JSON**")
    st.text_area("SOAR", value=D['export']['soar_json'], height=300,
                 key="soar_json", label_visibility="collapsed")
    st.download_button("📥 Download SOAR JSON", D['export']['soar_json'],
                       "sherlock_soar.json", "application/json", key="soar_dl")
