# SHERLOCK v20 — FULL TECHNICAL AUDIT REPORT

**Auditor:** Senior Security Engineer / Software Architect  
**Date:** 2026-02-22  
**Codebase:** Single-file Streamlit application, ~10,540 lines  
**Scope:** Architecture, performance, scoring system, code quality  

---

## EXECUTIVE SUMMARY

Sherlock is a single 10,540-line Python file that attempts to be simultaneously: an email parser, authentication analyzer, BEC/NLP engine, YARA scanner, PDF security engine, image forensics suite, multi-API threat intelligence client, nonlinear probabilistic scoring engine, risk narrative generator, SQLite case management system, REST API server, SOAR integration platform, and a full Streamlit UI with 9 tabs of complex HTML rendering.

The tool has accumulated 20 major versions of incremental fixes, each solving the previous version's problems but adding new complexity. The result is an architecturally overloaded monolith where **analysis, scoring, narrative generation, and UI rendering are inseparable**. The codebase is a cautionary example of what happens when a tool is patched forward instead of being redesigned at the right inflection point.

The performance issue (report takes too long to appear/render) has **two root causes**: (1) serial/slow TI enrichment is well-understood and partially addressed by v20, but (2) **the UI rendering itself is the dominant remaining bottleneck** — the `main()` function generates thousands of lines of inline HTML for every Streamlit render pass, recomputes derived data on every tab click, and the scoring+narrative subsystems re-derive data that was already computed during analysis.

---

## 1. ARCHITECTURE ANALYSIS

### 1.1 Overall System Design

**Finding: God-object monolith with no separation of concerns.**

The entire application lives in a single file with no module boundaries. The file contains:

| Concern | Lines (approx.) | Should be |
|---------|-----------------|-----------|
| Constants/config/keyword defs | 1–1,200 | `config/` module |
| YARA source + repair logic | 914–1,447 | `yara_engine.py` |
| Data classes | 1,450–1,580 | `models.py` |
| Scoring engine | 1,580–2,095 | `scoring/engine.py` |
| Risk narrative builder | 2,095–2,535 | `scoring/narrative.py` |
| Text processing | 2,535–2,580 | `parsers/text.py` |
| URL heuristics | 2,582–2,720 | `analysis/url.py` |
| Sender memory (SQLite) | 2,724–2,802 | `storage/sender_db.py` |
| Utility functions | 2,804–3,245 | `utils.py` |
| Domain intelligence | 3,288–3,525 | `analysis/domain.py` |
| VT/AbuseIPDB/OTX/XForce | 3,527–4,035 | `intel/` package |
| Auth analysis | 4,037–4,234 | `analysis/auth.py` |
| Header analysis | 4,236–4,290 | `analysis/headers.py` |
| BEC engine | 4,292–4,436 | `analysis/bec.py` |
| Display name spoof | 4,438–4,495 | `analysis/spoof.py` |
| YARA scanning | 4,500–4,595 | `yara_engine.py` |
| PDF security engine | 4,597–4,942 | `analysis/pdf.py` |
| Attachment analysis | 4,966–5,324 | `analysis/attachments.py` |
| Observable extraction | 5,326–5,720 | `parsers/observables.py` |
| Image analysis | 5,722–5,770 | `analysis/images.py` |
| Signal generation | 5,772–6,306 | `scoring/signals.py` |
| Attachment risk matrix | 6,308–6,368 | `analysis/attachment_risks.py` |
| Content analysis helpers | 6,370–6,406 | `analysis/content.py` |
| SOAR/Case DB/REST API | 6,408–7,166 | `integration/` package |
| Report generation | 7,168–7,418 | `reports/` package |
| Main orchestrator | 7,420–7,958 | `pipeline.py` |
| Reasoning cards + UI rendering | 7,960–10,540 | `ui/` package |

This is not just a readability problem — it means **every Streamlit rerun re-parses 10,540 lines of Python**, including compiling regex patterns, evaluating data structures, and initializing caches, even when most of the code is unreachable in a given render pass.

### 1.2 Tightly Coupled Logic

**Finding: Analysis results are structurally inseparable from their rendering.**

The `main()` function (lines 8,242–10,540 — **2,298 lines**) mixes:
- Analysis orchestration (`analyze_email()` call)
- Session state management
- Inline HTML generation via f-strings (thousands of lines)
- Repeated re-derivation of display data (`_obs_display_level()`, `_render_observable()` are nested functions)
- Score breakdown computation (duplicated from `run_scoring_engine`)
- Conditional UI branching based on verdict
- SOAR integration UI

Critical coupling points:
1. `build_reasoning_cards()` (lines 8,031–8,236) re-accesses raw `R['auth']`, `R['abuse_data']`, `R['macros']`, `R['images']`, and `R['signals']` to recompute display decisions that the scoring engine already made.
2. `build_risk_narrative()` (lines 2,100–2,534) re-calls `_detect_clusters()` and re-sorts signals, duplicating work from `run_scoring_engine()`.
3. The "Explain My Score" panel (lines 8,930–9,300) re-derives step-by-step breakdown from `score_breakdown` dict, but also independently computes `_n_real`, `_n_trust`, `_n_esc`, `_n_corrs` by re-filtering the raw signals list.

### 1.3 Unnecessary Control Layers

**Finding: The scoring pipeline has 7+ independent control mechanisms that interact unpredictably.**

The score passes through these sequential transformations:

```
Raw signal probabilities
  → Category density guard (diminishing returns per category)
    → Probability combination: P = 1 - Π(1 - p_i × c_i × density_weight)
      → Pairwise correlation bonuses (27 pairs × min confidence scaling)
        → Cluster detection + 8 conditional escalation rules (with density multiplier)
          → Trust factor dampening (multiplicative)
            → Signal hierarchy floors (tier-1 + tier-2 floors, auth-aware)
              → Verdict mapping (5 buckets)
                → Legacy confidence (hardcoded)
                → Analysis confidence (14-variable formula)
```

Additionally, **before** signals reach the scoring engine, the BEC subsystem applies its own independent control stack:
- Tier-based ceiling rules (0.10 / 0.18 / 0.42 caps)
- Combination boosters (6 rules)
- Category-count gates
- Short-email dampening
- Auth-context dampening in `generate_signals()` (0.35x or 0.70x multiplier)

This creates **9 distinct layers** that can cap, boost, floor, dampen, or gate the score. Each was added to fix a false-positive or false-negative from the previous layer, creating a Rube Goldberg machine where tuning any one parameter can have non-obvious cascading effects through 3-4 other layers.

### 1.4 Analysis and Rendering Intertwined

**Finding: The UI tab rendering code directly accesses raw analysis data and re-derives display logic.**

Examples:
1. **Tab 2 (URLs)**: The `_obs_display_level()` function (line 9,631) re-checks `is_tracking_domain()`, re-accesses `o.vt.domain_intel`, and re-classifies every observable — logic that should be pre-computed during analysis.
2. **Tab 3 (Attachments)**: Lines 9,843–9,850 recompute `eff_score` by applying a floor to `m.risk_score` based on `m.verdict` and `m.has_macros` — this adjustment should live in `analyze_attachment()`.
3. **Tab 4 (YARA)**: Lines 9,896–9,984 re-call `_get_yara()` and `_external_yara_path()` purely for a status banner, potentially re-triggering file system checks.
4. **Tab 0 (Report)**: Lines 8,585–8,930 generate the threat narrative display, re-parse the narrative markdown with regex, build HTML from cluster data, and construct signal cards — all inline in the rendering loop.

### 1.5 Scoring Complexity Inflation

**Finding: The scoring system has grown from a simple weighted sum to a 9-layer nonlinear pipeline to address edge cases that simpler architecture would prevent.**

Evidence:
- `SIGNAL_CORRELATIONS`: 27 manually defined pairwise rules
- `CLUSTER_ESCALATIONS`: 8 multi-cluster escalation rules with density multipliers
- `CATEGORY_DENSITY_THRESHOLDS`: per-category diminishing returns
- `BEC_KEYWORDS` tier system with 3 tiers × ceiling rules × combination boosters
- `_compute_analysis_confidence()`: 14 independent variables combined into a single 0–100 score
- The scoring engine itself (`run_scoring_engine`) is 250 lines of dense probability math

Each of these mechanisms was added to solve a specific regression. The result is that the scoring system's behavior is **not locally predictable** — changing one signal's probability can cascade through correlations, clusters, floors, and dampening in non-obvious ways.

---

## 2. PERFORMANCE ANALYSIS

### 2.1 Why the Report Takes Too Long to Appear/Render

**Root Cause 1: UI Rendering Weight (dominant after v20 VT fixes)**

The `main()` function generates inline HTML via Python f-strings for every UI element. A single render pass for a threat verdict generates:

- Verdict card: ~50 lines of HTML
- Narrative section: ~200 lines of HTML (phased sections, cluster badges, signal cards)
- Reasoning cards: ~8 cards × ~20 lines each = 160 lines
- Mitigating factors + correlations: ~100 lines
- "Explain My Score" panel: ~300 lines of HTML
- Each of 9 tabs: ~100–400 lines of HTML per tab
- Observable cards: ~50 lines per observable × 25 observables = 1,250 lines

**Total: ~3,000–5,000 lines of HTML generated per render pass**, all via Python f-string concatenation with `st.markdown(unsafe_allow_html=True)`.

This is repeated on every Streamlit interaction (tab click, sidebar toggle, etc.) because Streamlit re-runs the entire script top-to-bottom. The `st.rerun()` at line 8,497 was added specifically to prevent mid-render state mutations, but it means every analysis triggers **two full render passes**.

**Root Cause 2: Redundant Computation During Rendering**

Functions called during render that repeat analysis work:
- `build_reasoning_cards()`: re-iterates all signals, macros, images, observables
- `generate_text_report()`: re-iterates all signals, trust factors, correlations, macros (cached since v16-D but still generated once)
- `generate_analyst_report()`: re-iterates all observables, macros, generates report text
- `build_soar_json()`: re-iterates all signals, observables, macros, trust factors
- `map_mitre()`: re-iterates all signals
- `extract_iocs()`: re-iterates all observables, macros
- `_detect_clusters()`: called at least 3 times: once in `run_scoring_engine`, once in `build_risk_narrative`, once in the result dict construction at line 7,931

### 2.2 Repeated Full-Text Scans

1. **`normalize_text()` called 3 times on the same text**: Once in `analyze_email` (line 7,460), once inside `analyze_bec` (line 4,324), once inside `detect_suspicious_language` (line 6,392).

2. **`extract_visible_text()` + BS4 parsing runs twice**: Once in `analyze_email` (line 7,459) for `visible_text`, once in `extract_observables` (line 5,661) which creates a second BS4 soup from `html_body`.

3. **Body regex scan (`PAT_URL.findall`)**: Runs on the full body at line 5,707 AND again inside `detect_suspicious_language()` which regex-scans the combined text for every phrase in `SUSPICIOUS_PHRASES`.

4. **BEC keyword scanning**: `analyze_bec()` iterates all 82+ BEC keywords with `re.search(re.escape(kw), combined)` — one regex compilation and match per keyword per email.

### 2.3 Redundant Loops

1. **`domain_intel()` double-call pattern**: Despite the `_DOMAIN_INTEL_CACHE`, the first call for each domain still runs the full classification gauntlet: GOVERNMENT_TLDS (44 entries), EDUCATIONAL_TLDS (52 entries), KNOWN_PLATFORMS (48 entries), MAJOR_TECH (8 entries), and TRACKING_ALLOWLIST (40 entries) — all via linear iteration.

2. **`_root_domain()` compound TLD scan**: Called on every domain, iterates 150+ compound TLDs via linear string matching (`dl.endswith('.' + cc)`). Called from `is_tracking_domain()`, `check_typosquat()`, `domain_intel()`, `extract_observables()`, `generate_signals()`, and `_url_structure_heuristics()`. A single observable can trigger 6+ calls to `_root_domain()`.

3. **YARA match string extraction**: Both `_yara_scan()` and `_yara_scan_email()` contain identical 15-line string extraction blocks (lines 4,512–4,528 and 4,562–4,578). This is copy-pasted code, not a shared function.

4. **`msg.walk()` called 3 times**: Once in `analyze_email` for body extraction (line 7,445), once for attachment/image collection (line 7,530), once in `get_attachment_risks()` (line 6,313). Each walk traverses the full MIME tree.

### 2.4 O(n × signals) Patterns

1. **`_detect_clusters()`**: For each of 4 clusters × each signal, checks membership in the cluster's signal list AND performs wildcard prefix matching against all `*`-suffixed entries. Cost: O(signals × clusters × cluster_signals).

2. **Correlation bonuses**: For each of 27 correlation pairs, performs `next((s for s in signals if s.name == n1), None)` — a linear scan of all signals per pair. Cost: O(27 × signals).

3. **Signal generation TI emission** (lines 6,244–6,303): Builds `_seen_tier1_norm` by iterating all signals, then for each observable, iterates `_seen_otx` and `_seen_tier1_norm`. Cost: O(signals + observables × signals).

### 2.5 Heavy String Concatenation in Rendering

The `main()` function uses f-string concatenation to build HTML. Each `st.markdown()` call constructs a multi-line HTML string in Python memory. The observable rendering loop (lines 9,661–9,787) builds ~50 lines of HTML per observable inside a `st.expander`, with nested `_render_observable()` calls that themselves call `_obs_display_level()`, `is_tracking_domain()`, `_url_host()`, and `_esc()` multiple times per observable.

The "Explain My Score" panel alone (lines 8,930–9,298) generates ~370 lines of inline HTML with multiple `st.markdown()` calls, each requiring Streamlit to process and inject into the React frontend.

---

## 3. SCORING SYSTEM EVALUATION

### 3.1 Overcontrolled System

**Finding: The scoring system is significantly overcontrolled. Multiple control mechanisms overlap and partially conflict.**

The system applies 9 sequential transformation layers (enumerated in §1.3). The intent of each layer is defensible in isolation, but their combined effect is:

1. **Score compression toward the middle**: The combination of probability-product scoring (which naturally saturates toward 1.0 but slowly), correlation bonuses (which add diminishing fractions), and dampening (which multiplicatively removes) creates a natural attractor around 40-65 points. Emails need extreme evidence to reach 85+ or stay below 18.

2. **Floor/ceiling conflicts**: BEC tier ceilings (0.42 max for single tier-1 hit) can be overridden by cluster escalation bonuses that push the combined score past the ceiling the BEC engine tried to enforce. The BEC engine caps at MEDIUM, then `run_scoring_engine` can escalate to HIGH via cluster bonus — defeating the purpose of the cap.

3. **Auth-context dampening vs. trust factor dampening double-dip**: `generate_signals()` applies 0.35x/0.70x dampening to BEC scores based on auth state (line 5,886), and then `run_scoring_engine()` applies trust factor dampening from `spf_pass`/`dkim_pass`/`dmarc_pass` to the entire combined score. The BEC component is thus dampened twice — once content-specifically, once globally.

### 3.2 Mid-Score Clustering

**Finding: Scores cluster in the 35-65 range due to mathematical properties of the scoring formula.**

The probability combination formula `P = 1 - Π(1 - p_i × c_i)` has a specific mathematical property: with signals in the 0.15-0.35 range (which is where most tier-3 and tier-4 signals live after density weighting), the combined probability converges slowly. For example:

- 3 signals at effective 0.20 each: P = 1 - (0.8)^3 = 0.488 (49%)
- 5 signals at effective 0.20 each: P = 1 - (0.8)^5 = 0.672 (67%)
- Adding a 6th: P = 0.738 (74%) — only +7 points

This means going from "SUSPICIOUS" to "LIKELY MALICIOUS" requires either:
- A single high-probability signal (tier-1/tier-2), OR
- A cluster escalation bonus, OR
- Many co-firing correlations

The result is that emails with 3-5 weak signals pile up at 40-55, and the escalation bonuses are the primary mechanism that lifts them. This makes the cluster/escalation system the de facto scoring gatekeeper, not the signal probabilities themselves.

### 3.3 Escalation Logic Coherence

**Finding: Escalation rules can fire cumulatively, creating unpredictable score jumps.**

The 8 `CLUSTER_ESCALATIONS` rules are checked independently — if spoof+payload fires, spoof+social_engineering fires, AND spoof+infra fires, all three bonuses stack. For an email with signals in all four clusters:

- `spoof+payload`: +0.25 × conf × density
- `spoof+social_engineering`: +0.18 × conf × density
- `spoof+infrastructure`: +0.12 × conf × density
- `infra+social_engineering`: +0.15 × conf × density
- `payload+infrastructure`: +0.20 × conf × density
- Triple-vector (spoof+infra+social): +0.30 × conf × density
- Triple-vector (spoof+payload+social): +0.28 × conf × density
- Quad-vector: +0.35 × conf × density

That's 8 bonuses stacking additively (each applied as `combined + bonus × (1 - combined)`), which can push a 40-point email to 90+ purely from cluster geometry rather than actual evidence strength. The density multiplier (lines 1,851-1,852) partially mitigates this but only reduces each bonus to 50% minimum — the stack still compounds.

### 3.4 Confidence Score Ambiguity

**Finding: The analysis confidence score conflates two different questions into one number.**

`_compute_analysis_confidence()` answers:
- For clean emails: "How sure are we this is safe?" (auth passes, absence of signals)
- For threat emails: "How corroborated is the threat?" (signal count, diversity, clusters)

These are fundamentally different metrics being mapped to the same 0-100 scale. A score of 65 means completely different things depending on the verdict. The UI attempts to bridge this gap with conditional labels ("Confirmed Clean" vs "Strong") and conditional tooltips, but the underlying conflation means the number cannot be reliably compared across emails with different verdicts.

---

## 4. CODE QUALITY & MAINTAINABILITY

### 4.1 Large Functions

| Function | Lines | Responsibility Count |
|----------|-------|---------------------|
| `main()` | 2,298 | Session mgmt, analysis orchestration, 9 tab rendering, HTML generation, case management UI |
| `generate_signals()` | 534 | Auth signals, BEC dampening, header signals, spoof signals, URL signals, domain signals, VT signals, OTX signals, XForce signals, attachment signals, YARA signals, image signals, sender memory, DNSBL, MX validation |
| `analyze_email()` | 538 | Email parsing, body extraction, parallel body analysis, parallel scan orchestration, DNS classification, VT pipeline, signal generation, scoring, narrative building |
| `analyze_attachment()` | 358 | Hash computation, MalwareBazaar check, YARA scan, structural FP suppression, PDF analysis, Office analysis, OLE/VBA parsing, MacroRaptor |
| `build_risk_narrative()` | 434 | Signal filtering, evidence sentence generation (8 categories), behavioral pattern matching, prose composition, phase grouping, trust mitigations, recommendations |
| `run_scoring_engine()` | 250 | Density guard, probability combination, correlations, cluster detection, escalation, dampening, floors, verdict mapping, confidence computation, dominant vector |
| `_pikepdf_security_scan()` | 213 | PDF parsing, object graph walking, tag collection, JS extraction, URI extraction, embedded file detection, caching, timeout handling |
| `domain_intel()` | 110 | TLD classification (4 sets), platform matching, tracking domain check, WHOIS, DNS resolution, entropy analysis, DGA detection, caching |

Every function in this table is doing too much. `generate_signals()` at 534 lines is the canonical example: it's a 530-line function that converts every type of analysis result into signals, with completely unrelated concerns (BEC auth dampening, URL heuristics, YARA classification, DNSBL checking) in one sequential block.

### 4.2 Duplicated Logic

1. **Signal filtering**: The pattern `[s for s in signals if not (s.probability == 0.0 and s.name.startswith('bec_') and s.name != 'bec_combined')]` appears 6 times (lines 2,016, 2,127, 7,196, 8,591, 8,759, 10,195).

2. **YARA string extraction**: The ~15-line string extraction block is identical in `_yara_scan()` and `_yara_scan_email()`.

3. **Confidence labeling**: The confidence-to-label mapping (`"Confirmed Clean" if >= 75 else...`) is defined 3 separate times (lines 8,531–8,537, 8,539–8,549, 8,939–8,949).

4. **Observable rendering**: `_obs_display_level()` is defined as a nested function inside `main()` and called per-observable per-render. The same classification logic partially exists in `_apply_scores()` inside `analyze_email()`.

5. **Link mismatch deduplication**: The pattern of deduplicating by `(display_domain, href_domain)` pair is repeated 3 times (lines 5,923–5,928, 8,113–8,118, 9,591–9,597).

6. **Verdict-to-color/icon mapping**: `_tc()` and `_ti()` are called hundreds of times during rendering. Their lookup dicts are recreated on every call (though Python may optimize this via constant folding).

### 4.3 Readability Issues

1. **Inline HTML everywhere**: The UI code is ~2,500 lines of f-string HTML embedded in Python. This is impossible to maintain, debug, or hand off to a frontend developer. A single mismatched quote or brace breaks the entire page.

2. **Magic numbers throughout**: `0.35`, `0.70`, `0.42`, `0.18`, `0.10`, `4.0`, `3.5`, `0.25`, `0.02` — signal probabilities, dampening factors, entropy thresholds, and density ratios are scattered as inline literals with no named constants.

3. **Comment-heavy code masking complexity**: The codebase is densely commented (good for individual fixes) but the comment density masks the fact that the underlying logic is too complex. Comments explain *why each hack exists* rather than questioning whether the hack should exist.

4. **Hungarian notation in places**: `_SENDER_DB_DIR_FOR_YARA`, `_PIKEPDF_CACHE_LOCK`, `_DOMAIN_INTEL_CACHE_LOCK` — inconsistent naming conventions between module globals.

### 4.4 Architectural Rigidity

1. **Adding a new signal type requires changes in 4+ places**: Define in `THREAT_CLUSTERS`, add to `SIGNAL_CORRELATIONS`, emit in `generate_signals()`, handle in `build_risk_narrative()`, and possibly add display logic in the UI tab.

2. **Adding a new TI source requires changes in 6+ places**: API client function, cache instance, enrichment in `_enrich_otx_xforce()`, signal emission in `generate_signals()`, display in `_render_observable()`, and SOAR JSON builder.

3. **Tuning a single false-positive requires understanding 9 layers**: Change the signal probability → verify it doesn't change category density behavior → check correlation interactions → verify cluster membership → check escalation bonuses → verify dampening interactions → check floor behavior → verify verdict mapping → verify narrative output.

4. **No test infrastructure**: Zero test files. The simulation mode (sidebar feature) is the only "testing" mechanism. This means every change is tested by running the full Streamlit app with a real .eml file.

---

## 5. PRIORITIZED EXECUTION PLAN

### Phase 2: Backend Restructure (files + pipeline)

**Step 1: Extract data models and constants into separate modules**
- `models.py`: All dataclasses (ThreatSignal, TrustFactor, VTResult, etc.)
- `constants.py`: All keyword sets, TLD lists, regex patterns, thresholds
- `config.py`: Config class, API keys, paths
- Impact: Zero behavioral change, pure extraction

**Step 2: Extract analysis modules into a package**
- `analysis/auth.py`: `analyze_auth()`, `_dns_dmarc()`, `_dns_spf()`
- `analysis/bec.py`: `analyze_bec()`, BEC_KEYWORDS, tier logic
- `analysis/headers.py`: `analyze_headers()`, `check_display_spoof()`
- `analysis/attachments.py`: `analyze_attachment()`, `_yara_scan()`, PDF engine
- `analysis/observables.py`: `extract_observables()`, URL heuristics
- `analysis/images.py`: `analyze_image()`
- `analysis/domain.py`: `domain_intel()`, `check_typosquat()`, entropy functions
- Impact: Same functions, just relocated. Tests become possible per-module.

**Step 3: Extract intel clients into a package**
- `intel/virustotal.py`: VT client, rate limiter, cache, consensus
- `intel/otx.py`: OTX client
- `intel/xforce.py`: X-Force client
- `intel/abuseipdb.py`: AbuseIPDB client
- `intel/malwarebazaar.py`: MalwareBazaar client
- `intel/spamhaus.py`: DNSBL check, MX validation
- Impact: Each TI source becomes independently testable and replaceable.

**Step 4: Simplify the scoring engine**
- Flatten the 9-layer scoring pipeline to 4 layers: combine → escalate → dampen → map
- Remove BEC-specific auth dampening from `generate_signals()` — let the scoring engine handle all dampening uniformly
- Replace the 27 manually defined correlation pairs with an automatic "same-email co-occurrence" bonus (signals from ≥3 different categories get a diversity bonus)
- Replace the 8 cluster escalation rules with a single rule: `escalation = base × (active_clusters / 4) × avg_confidence`
- Convert magic-number thresholds to named constants with documented rationale
- Impact: Scoring becomes locally predictable. Tuning one parameter has bounded effects.

**Step 5: Extract signal generation into a declarative registry**
- Replace the 534-line `generate_signals()` with a signal registry pattern: each analysis module registers its own signal-emitting function
- Signals are generated by the module that produced them (auth module emits auth signals, etc.)
- Impact: Adding a new signal type requires changes in 1 place, not 4+.

**Step 6: Restructure the main pipeline**
- `pipeline.py`: Pure orchestration — no rendering, no UI state
- Pre-compute ALL display data during analysis (observable classifications, attachment verdicts, tab summaries)
- Store a "display-ready report" dict that the UI can render without re-deriving anything
- Impact: UI rendering becomes a pure read of pre-computed data.

### Phase 3: Frontend Restructure

**Step 7: Extract UI into a `ui/` package**
- `ui/main.py`: App entry point, session state, tab routing
- `ui/verdict.py`: Verdict card rendering
- `ui/tabs/report.py`: Report & Intelligence tab
- `ui/tabs/auth.py`: Authentication tab
- `ui/tabs/urls.py`: URLs & Domains tab
- `ui/tabs/attachments.py`: Attachments tab
- `ui/tabs/yara.py`: YARA tab
- `ui/tabs/images.py`: Images tab
- `ui/tabs/findings.py`: All Findings tab
- `ui/tabs/export.py`: Export tab
- `ui/tabs/soc.py`: SOC Integration tab
- `ui/components.py`: Shared card/badge/table renderers

**Step 8: Replace inline HTML with Streamlit components**
- Convert f-string HTML to `st.container()`, `st.columns()`, `st.metric()`, and custom CSS via `st.markdown` only for theming
- Use `@st.cache_data` for expensive computations (narrative, reasoning cards, text report)
- Pre-render tab content as cached data, not live computation
- Impact: Render time drops from seconds to milliseconds on tab switch.

**Step 9: Performance-optimize the hot paths**
- Convert `_root_domain()` compound TLD list to a set lookup: `O(150 × endswith)` → `O(1) set membership`
- Pre-compute signal name sets once instead of re-deriving them in `_detect_clusters`, `build_risk_narrative`, correlation bonus loop
- Cache `_detect_clusters()` result on the ScoringResult rather than recomputing 3 times
- Pool `msg.walk()` into a single pass that collects all part data
- Batch `normalize_text()` — call once, pass the result downstream

### Phase 4: Quality Infrastructure

**Step 10: Add test infrastructure**
- Unit tests for each analysis module (auth, BEC, attachments, observables)
- Scoring engine regression tests (known input signals → expected score/verdict)
- Integration test with a set of known .eml files (benign, phishing, BEC, malware)
- Signal registry test: verify every registered signal has a corresponding cluster mapping and narrative handler

**Step 11: Performance benchmarking harness**
- Instrument `analyze_email()` with per-phase timing
- Add a `--profile` flag that outputs timing breakdown without launching the UI
- Set target: <5s for analysis, <1s for render on a standard email

---

This audit report is the foundation for Phase 2 and Phase 3 implementation. No code has been refactored yet — this report documents the current state and provides the architectural blueprint for the rebuild.
