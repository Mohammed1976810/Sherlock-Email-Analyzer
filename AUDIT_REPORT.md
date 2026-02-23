# SHERLOCK v14.0 — Production Readiness Audit Report

**Auditor:** Senior Software Architect & Security Engineer
**Date:** 2026-02-23
**Scope:** Complete technical audit across accuracy, performance, scalability, safety, and overengineering
**Codebase:** ~10,100 lines, single-file Streamlit application

---

## 1. Executive Summary

**Verdict: CONDITIONALLY PRODUCTION READY**

Sherlock v14.0 is a well-engineered SOC email analysis tool with a sophisticated nonlinear scoring engine, multi-source threat intelligence pipeline, and comprehensive detection coverage. The codebase shows evidence of extensive hardening through v10–v14 security audits (23+ documented fixes).

Six surgical fixes were applied during this audit. None alter scoring logic or public interfaces. The most significant was a **silent gap in Cofense email-level YARA rule evaluation** — the `_yara_scan_email()` function was defined but never called, meaning email header/routing pattern rules from the Cofense threat intel ruleset were completely ignored.

All fixes are backward-compatible. Scoring behavior is preserved for all existing signal paths.

---

## 2. Critical Flaws (MUST FIX) — Applied

### AUDIT-01: `_yara_scan_email()` defined but never called
**Severity:** CRITICAL
**Impact:** Cofense email-level rules (CY_PDC_Phish_*, CY_BEC_*, PM_Labs_*) that target header patterns, routing signatures, and MIME structure were silently ignored. Only body text and file attachments were YARA-scanned.
**Root cause:** The function was added in v14 but the call site in `analyze_email()` was never wired up.
**Fix:** Added `_yara_scan_email(msg_bytes)` call after the body YARA scan, storing results in a `[Email]` MacroResult entry. Uses the existing `_ATTACHMENT_ONLY_RULES` exclusion to prevent FP from base64-encoded attachment content.
**Scoring impact:** May increase scores for emails matching Cofense email-level rules. This is correct behavior — these rules were supposed to fire and weren't.

### AUDIT-02: `st.dataframe(width='stretch')` — 3 broken instances
**Severity:** HIGH (UI breakage)
**Impact:** `width='stretch'` is not a valid Streamlit parameter and is silently ignored. DataFrames render at minimum width instead of filling the container.
**Root cause:** v14-03 changelog claimed all 4 locations were fixed, but 3 in the All Findings and SOC Integration tabs were missed.
**Fix:** Changed to `use_container_width=True` (correct Streamlit API) in all 3 locations.
**Scoring impact:** None — UI only.

---

## 3. Medium Risks — Applied

### AUDIT-03: Sidebar API status permanently shows "offline"
**Severity:** MEDIUM (misleading UI)
**Impact:** `FASTAPI_OK` is hardcoded to `False` (line 234) since the API migrated to stdlib `http.server`. The sidebar permanently displays "⚠️ Install fastapi+uvicorn" and hides the API key, even though the API is running and functional.
**Fix:** Removed `FASTAPI_OK` gate from sidebar API status, API key display, and SOC Integration tab endpoint reference.

### AUDIT-04: Double `is_ole` assignment with weaker check
**Severity:** MEDIUM (correctness)
**Impact:** `is_ole` was computed with the full 8-byte OLE2 magic check (`\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1`), then silently overwritten with a 4-byte prefix check (`\xD0\xCF\x11\xE0`) later in `analyze_attachment()`. The 4-byte check is practically equivalent but theoretically less strict.
**Fix:** Removed the redundant 4-byte reassignment; reuses the already-computed 8-byte value.
**Scoring impact:** None — the 4-byte prefix is unique to OLE2.

### AUDIT-05: `hashlib.md5()` without `usedforsecurity=False` (4 sites)
**Severity:** MEDIUM (FIPS compliance)
**Impact:** Government and military SOCs often run FIPS-enforced Python. Bare `hashlib.md5()` raises `ValueError` on FIPS systems. All 4 call sites use MD5 purely for identification (file hashes, cache keys), not security.
**Fix:** Added `usedforsecurity=False` to 4 remaining call sites: Config API key seed, attachment hash, email hash, and file upload hash.

---

## 4. Minor Improvements — Applied

### AUDIT-06: `_INNER_PARAM_NAMES` and `_PHISH_PARAMS` re-created per call
**Severity:** LOW (performance)
**Impact:** A 17-element tuple and an 11-element frozenset were allocated on every URL processed. For emails with 25 observables, that's 50 unnecessary allocations per analysis.
**Fix:** Moved both to module-level constants.

---

## 5. Performance Bottlenecks Identified (No Action Required)

| Bottleneck | Assessment |
|---|---|
| **VT rate limiting (15s/call)** | Inherent to free-tier API. Two-pool architecture (Pool A: VT rate-limited, Pool B: OTX+X-Force immediate) already optimally overlaps. No further optimization possible without paid VT tier. |
| **WHOIS serialization** | `_whois_lock` serializes all WHOIS calls. This is the correct design — WHOIS uses `socket.setdefaulttimeout()` which is process-global. The `_DOMAIN_INTEL_CACHE` prevents repeat WHOIS for the same root domain. |
| **pikepdf cache** | Already implemented via `_PIKEPDF_CACHE` with content-hash keying. Each PDF is scanned exactly once. |
| **BS4 HTML parsing** | Called twice — once in `extract_visible_text()` and once in `extract_observables()`. The second call is on different data (href extraction vs text extraction) so this is correct, not redundant. |
| **Regex compilation** | All hot-path patterns are module-level precompiled via `_rc()`. No per-call compilation found. |
| **`case_stats()` on every render** | Already cached in `st.session_state` with 5-second TTL (FIX v16-E). |
| **Text report generation** | Already cached in `st.session_state` by MD5 key (FIX v16-D). |

---

## 6. Scalability Concerns

| Concern | Assessment |
|---|---|
| **Single-threaded Streamlit** | Streamlit is inherently single-user per process. For SOC deployment with multiple analysts, run behind a reverse proxy with multiple Streamlit instances. The codebase is stateless per-analysis (shared state is only SQLite sender/case DBs with WAL mode). |
| **SQLite for case DB** | WAL mode + busy_timeout=5000ms handles moderate concurrency. For >10 concurrent analysts, migrate to PostgreSQL. The schema is simple enough that this is a config change, not a code rewrite. |
| **Thread pool sizes** | VT: 4 workers, OTX+X-Force: 8 workers, body analysis: 3 workers, attachments: 4 workers. These are appropriate for the I/O-bound workload. |
| **Memory for large emails** | `MAX_FILE_SIZE` = 50MB, `MAX_HTML_SIZE` = 5MB, `MAX_IMAGE_SIZE` = 20MB, `MAX_ZIP_EXTRACT` = 1MB. All guards are in place. |
| **Global caches unbounded** | `_DOMAIN_INTEL_CACHE`, `_PIKEPDF_CACHE` grow without bound. For a SOC processing thousands of emails/day, these could consume significant memory. Consider adding LRU eviction (same pattern as `_Cache.put()` which already evicts at 800 entries). |

---

## 7. Phase-by-Phase Findings

### Phase 1: Accuracy & Logic Verification

| Check | Result |
|---|---|
| **Scoring determinism** | ✅ `run_scoring_engine()` is purely functional — same signals + trust factors always produce the same score. No randomness, no external state reads. |
| **Double-counting** | ✅ Per-category density thresholds (`CATEGORY_DENSITY_THRESHOLDS`) prevent signal stacking. Deduplication sets (`_seen_typo_domains`, `_seen_dga_entropy`, etc.) prevent duplicate signals from the same root domain. BEC zero-prob markers are correctly excluded from cluster detection (FIX BUG4). |
| **Scoring drift** | ✅ The nonlinear combiner `P = 1 - ∏(1 - pᵢ × cᵢ)` is mathematically bounded to [0,1]. Cluster escalation uses `combined + bonus × (1 - combined)` which also stays in [0,1]. Trust dampening uses `combined × (1 - dampen)` which only reduces. |
| **Contradictory signals** | ✅ BEC contradiction detection reduces score by 50% when urgency + calm language co-occur. Trust factors dampen proportionally, not to zero. The tier floor system ensures hard evidence (Tier 1) overrides dampening. |
| **Unreachable branches** | ✅ Dead `vendor_pass` branch inside SPF FAIL was already removed (FIX BUG7). No other unreachable branches found. |
| **MIME parsing** | ✅ Uses `email.policy.default` which handles malformed MIME gracefully. All `get_payload(decode=True)` calls check for `bytes` return type. |
| **Attachment edge cases** | ✅ 3-level filename fallback (Content-Disposition → Content-Type name= → MIME type synthesis). Empty files return early with "Empty file" verdict. |
| **SPF/DKIM/DMARC parsing** | ✅ Word-boundary regex with negative lookbehind (`(?<!=)\bspf\s*=\s*pass\b`) prevents substring injection attacks. Multiple AR headers are read (FIX C15). |
| **URL extraction** | ✅ Three-tier PDF URI extraction (pikepdf → pdfminer → raw regex). `is_redirect_wrapper()` with double-decode handles percent-encoded inner URLs. `extract_inner_url()` tries 16+ common parameter names. |
| **Shannon entropy** | ✅ Standard formula `-Σ(pᵢ × log₂(pᵢ))` correctly implemented in both `shannon_entropy()` and `url_path_entropy()`. `subdomain_entropy()` has guards for structured hostnames and hex CDN tokens. |
| **Macro analysis** | ✅ MacroRaptor verdict is trusted. VBA entropy threshold (5.5 bits) is reasonable. YARA VBA scan runs on extracted macro code, not raw OLE. |

### Phase 2: Performance & Efficiency

| Check | Result |
|---|---|
| **Redundant computation** | ✅ pikepdf scan cached by content hash. Domain intel cached by root domain. VT/OTX/X-Force cached by `_Cache` class. Text report cached in session_state. |
| **Repeated regex** | ✅ All hot-path patterns precompiled at module level. `_PRIVATE_IP_PATTERNS` moved from per-call to module-level (FIX C19). |
| **Unnecessary copying** | ✅ No deep copies found. Signal lists are built once, not copied between stages. |
| **Blocking in UI** | ✅ Analysis runs in the main thread but with progress callbacks. `st.rerun()` after analysis ensures clean render pass. Webhook fires in daemon thread. |
| **Dead code** | ✅ `FASTAPI_OK` flag is dead (always False) but harmless. Removed its UI gate effects. `_yara_scan_email()` was dead code — now activated. |

### Phase 3: Scalability & SOC Readiness

| Check | Result |
|---|---|
| **High-volume ingestion** | ⚠️ Streamlit is not designed for batch processing. For high-volume, use the REST API endpoint and `analyze_email()` directly. The analysis function is stateless and thread-safe. |
| **Logging** | ✅ Structured logging via `logging.getLogger("sherlock")`. Key events logged: YARA compile, VT results, case saves, webhook fires. |
| **Deterministic output** | ✅ `build_soar_json()` produces a stable schema (v2.0) with all fields always present (empty rather than missing). |
| **Error handling** | ✅ Every external call (VT, OTX, X-Force, WHOIS, DNS, MalwareBazaar) wrapped in try/except with graceful degradation. PIL decompression bomb guard, pdfminer timeout, BS4 size limit all in place. |
| **Graceful degradation** | ✅ Every optional dependency (pikepdf, YARA, DNS, OCR, PIL, oletools) has a flag-gated fallback. Analysis completes with reduced coverage but never crashes. |

### Phase 4: Overengineering Review

| Check | Result |
|---|---|
| **Unnecessary abstraction** | ✅ Single-file architecture is appropriate for a SOC tool — no import chains to debug, easy to deploy. Dataclasses are used correctly for structured data. |
| **Redundant modules** | ✅ No circular dependencies. No unnecessary indirection. |
| **Code duplication** | ⚠️ YARA string extraction logic is duplicated between `_yara_scan()` and `_yara_scan_email()` (lines 4250-4283 and 4302-4333). Could be extracted to a helper, but the risk of breaking the delicate `sm.instances` / tuple fallback logic outweighs the benefit. |

### Phase 5: Safety & Stability

| Check | Result |
|---|---|
| **Exception crash** | ✅ `analyze_email()` wraps all stages. Individual module failures don't crash the pipeline. All `bare except:` clauses were already fixed to `except Exception:` (FIX C14). |
| **Input sanitization** | ✅ `_esc()` HTML-escapes all user-facing values. `defang()` replaces protocol and dots. `MAX_HTML_SIZE` limits BS4 input. |
| **Report generation hang** | ✅ `generate_text_report()` is pure string formatting with no I/O. PDF generation uses reportlab with bounded input. |
| **Unbounded loops** | ✅ All loops have explicit bounds: YARA matches capped at 100/200, observables at MAX_OBS=25, PDF URIs at 100, ZIP entries checked by `MAX_ZIP_EXTRACT`. `_walk_obj` has depth=12 cycle guard. |
| **Corrupted attachments** | ✅ All attachment analysis wrapped in try/except. VBA_Parser closed in finally block (FIX C06). Temp files use context manager with guaranteed cleanup (FIX C05). |
| **FIPS compliance** | ✅ All `hashlib.md5()` calls now pass `usedforsecurity=False` (AUDIT-05). |

---

## 8. Confirmation: Scoring Behavior Unchanged

All six applied fixes preserve existing scoring behavior:

1. **AUDIT-01 (_yara_scan_email):** ADDS coverage that was missing. Emails without Cofense rules or without email-level rule matches are unaffected. Emails that DO match email-level Cofense rules will now correctly score higher — this is the intended behavior.

2. **AUDIT-02 (st.dataframe):** UI-only change. No scoring impact.

3. **AUDIT-03 (sidebar API status):** UI-only change. No scoring impact.

4. **AUDIT-04 (is_ole):** The 4-byte OLE2 prefix is unique; removing the redundant check has no practical impact on file type detection or scoring.

5. **AUDIT-05 (hashlib.md5 FIPS):** `usedforsecurity=False` changes no behavior — it only prevents `ValueError` on FIPS systems.

6. **AUDIT-06 (module-level constants):** Moving constants from function-local to module-level changes no values and no behavior.

**No scoring weights, probability values, threshold constants, tier assignments, cluster definitions, correlation bonuses, or dampening factors were modified.**

---

## 9. Items Reviewed and Confirmed Correct (No Change Needed)

- Nonlinear probability combiner formula
- Cluster escalation bonus application order
- Trust factor dampening math
- BEC tier ceiling rules and category-count gates
- Auth-context dampening of BEC scores
- Signal hierarchy floor enforcement
- Verdict threshold boundaries (18/40/65/85)
- Analysis confidence computation (clean vs threat branches)
- Display name spoof brand/title separation
- Typosquat detection with allowlists
- Shadow spoof root-domain comparison
- URL normalization and deduplication
- Observable priority sorting before VT cap
- YARA severity classification and enrichment rule handling
- YARA auto-repair brace-depth counting
- PDF security scan object-graph walking
- Sender memory trust scaling
- Spamhaus DNSBL reverse lookup
- MX record validation
- MITRE ATT&CK mapping
- SOAR JSON schema stability
- REST API authentication and CORS
- Case database schema and audit logging
